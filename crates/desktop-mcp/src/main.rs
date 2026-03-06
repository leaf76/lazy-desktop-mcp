use anyhow::{Context, Result, anyhow};
use desktop_core::{
    Capability, Coordinate, HostEnvelope, HostRequest, HostResponse, SessionPolicy, ToolError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolDefinition {
    name: &'static str,
    description: &'static str,
    input_schema: Value,
}

#[derive(Debug, Deserialize)]
struct CallToolParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Debug, Deserialize)]
struct SessionPolicyArgs {
    #[serde(default)]
    capabilities: Vec<Capability>,
    #[serde(default)]
    allowed_apps: Vec<String>,
    #[serde(default)]
    allowed_windows: Vec<String>,
    #[serde(default)]
    allowed_screens: Vec<String>,
    #[serde(default)]
    allow_raw_input: bool,
    #[serde(default)]
    dry_run: bool,
    #[serde(default = "default_action_budget")]
    max_actions_per_minute: usize,
}

fn default_action_budget() -> usize {
    60
}

impl From<SessionPolicyArgs> for SessionPolicy {
    fn from(value: SessionPolicyArgs) -> Self {
        Self {
            capabilities: BTreeSet::from_iter(value.capabilities),
            allowed_apps: value.allowed_apps,
            allowed_windows: value.allowed_windows,
            allowed_screens: value.allowed_screens,
            allow_raw_input: value.allow_raw_input,
            dry_run: value.dry_run,
            max_actions_per_minute: value.max_actions_per_minute,
        }
    }
}

struct HostClient {
    _child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
}

impl HostClient {
    async fn spawn() -> Result<Self> {
        let host_binary = resolve_host_binary()?;
        let mut child = Command::new(host_binary)
            .arg("--stdio-host")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .context("failed to start desktop-host")?;

        let stdin = child
            .stdin
            .take()
            .context("desktop-host stdin was not piped")?;
        let stdout = child
            .stdout
            .take()
            .context("desktop-host stdout was not piped")?;

        Ok(Self {
            _child: child,
            stdin: BufWriter::new(stdin),
            stdout: BufReader::new(stdout).lines(),
        })
    }

    async fn call(&mut self, request: &HostRequest) -> Result<Result<HostResponse, ToolError>> {
        self.stdin
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;

        let line = self
            .stdout
            .next_line()
            .await?
            .ok_or_else(|| anyhow!("desktop-host exited before replying"))?;
        let envelope: HostEnvelope = serde_json::from_str(&line)?;
        Ok(match envelope {
            HostEnvelope::Ok { response } => Ok(response),
            HostEnvelope::Err { error } => Err(error),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .with_writer(std::io::stderr)
        .init();

    let mut host = HostClient::spawn().await?;
    let stdin = BufReader::new(io::stdin());
    let mut stdout = BufWriter::new(io::stdout());
    let mut lines = stdin.lines();
    let mut initialized = false;

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let request = match serde_json::from_str::<JsonRpcRequest>(&line) {
            Ok(request) => request,
            Err(error) => {
                let response = JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: None,
                    result: None,
                    error: Some(RpcError {
                        code: -32700,
                        message: format!("Failed to parse JSON-RPC request: {error}"),
                        data: None,
                    }),
                };
                stdout
                    .write_all(serde_json::to_string(&response)?.as_bytes())
                    .await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
                continue;
            }
        };

        let response = handle_request(&mut host, &mut initialized, request).await?;
        if let Some(response) = response {
            stdout
                .write_all(serde_json::to_string(&response)?.as_bytes())
                .await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }

    Ok(())
}

async fn handle_request(
    host: &mut HostClient,
    initialized: &mut bool,
    request: JsonRpcRequest,
) -> Result<Option<JsonRpcResponse>> {
    match request.method.as_str() {
        "initialize" => {
            *initialized = true;
            Ok(Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: Some(json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "desktop-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
                error: None,
            }))
        }
        "notifications/initialized" => Ok(None),
        "ping" => Ok(Some(JsonRpcResponse {
            jsonrpc: "2.0",
            id: request.id,
            result: Some(json!({})),
            error: None,
        })),
        "tools/list" => {
            if !*initialized {
                return Ok(Some(protocol_error(
                    request.id,
                    -32002,
                    "Server must be initialized before listing tools.",
                )));
            }
            Ok(Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: Some(json!({ "tools": tool_definitions() })),
                error: None,
            }))
        }
        "tools/call" => {
            if !*initialized {
                return Ok(Some(protocol_error(
                    request.id,
                    -32002,
                    "Server must be initialized before calling tools.",
                )));
            }

            let params: CallToolParams = match serde_json::from_value(request.params) {
                Ok(params) => params,
                Err(error) => {
                    return Ok(Some(tool_error_response(
                        request.id,
                        ToolError::validation(
                            format!("Invalid tool call payload: {error}"),
                            Uuid::new_v4().to_string(),
                        ),
                    )));
                }
            };
            let trace_id = Uuid::new_v4().to_string();
            let host_request = match build_host_request(&params.name, params.arguments, &trace_id) {
                Ok(host_request) => host_request,
                Err(error) => {
                    return Ok(Some(tool_error_response(
                        request.id,
                        ToolError::validation(error.to_string(), trace_id),
                    )));
                }
            };
            let host_result = match host.call(&host_request).await {
                Ok(host_result) => host_result,
                Err(error) => {
                    return Ok(Some(tool_error_response(
                        request.id,
                        ToolError::internal(
                            format!("The desktop host is unavailable: {error}"),
                            trace_id,
                        ),
                    )));
                }
            };

            let result = match host_result {
                Ok(response) => json!({
                    "content": [
                        {
                            "type": "text",
                            "text": summarize_response(&response)
                        }
                    ],
                    "structuredContent": serde_json::to_value(response)?,
                    "isError": false
                }),
                Err(error) => json!({
                    "content": [
                        {
                            "type": "text",
                            "text": format!("{:?}: {}", error.code, error.message)
                        }
                    ],
                    "structuredContent": {
                        "error": error
                    },
                    "isError": true
                }),
            };

            Ok(Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: Some(result),
                error: None,
            }))
        }
        _ => Ok(Some(protocol_error(
            request.id,
            -32601,
            "Unsupported JSON-RPC method.",
        ))),
    }
}

fn protocol_error(id: Option<Value>, code: i32, message: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError {
            code,
            message: message.to_string(),
            data: None,
        }),
    }
}

fn tool_error_response(id: Option<Value>, error: ToolError) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(json!({
            "content": [
                {
                    "type": "text",
                    "text": format!("{:?}: {}", error.code, error.message)
                }
            ],
            "structuredContent": {
                "error": error
            },
            "isError": true
        })),
        error: None,
    }
}

fn resolve_host_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("DESKTOP_HOST_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }

        return Err(anyhow!(
            "DESKTOP_HOST_BIN does not point to an existing host binary: {}",
            path.display()
        ));
    }

    let current_exe =
        std::env::current_exe().context("failed to resolve current executable path")?;
    let executable_name = if cfg!(windows) {
        "desktop-host.exe"
    } else {
        "desktop-host"
    };
    let sibling = current_exe
        .parent()
        .context("desktop-mcp executable has no parent directory")?
        .join(executable_name);

    if sibling.exists() && sibling.is_file() {
        return Ok(sibling);
    }

    Err(anyhow!(
        "desktop-host was not found next to desktop-mcp. Set DESKTOP_HOST_BIN to an absolute path."
    ))
}

fn build_host_request(name: &str, arguments: Value, trace_id: &str) -> Result<HostRequest> {
    match name {
        "desktop.capabilities" => Ok(HostRequest::GetCapabilities {
            trace_id: trace_id.to_string(),
        }),
        "desktop.permissions" => Ok(HostRequest::GetPermissions {
            trace_id: trace_id.to_string(),
        }),
        "session.open" => {
            let args: SessionPolicyArgs = serde_json::from_value(arguments)?;
            Ok(HostRequest::OpenSession {
                trace_id: trace_id.to_string(),
                policy: args.into(),
            })
        }
        "session.close" => Ok(HostRequest::CloseSession {
            trace_id: trace_id.to_string(),
            session_id: read_uuid(&arguments, "session_id")?,
        }),
        "app.list" => Ok(HostRequest::ListApps {
            trace_id: trace_id.to_string(),
        }),
        "app.launch" => Ok(HostRequest::LaunchApp {
            trace_id: trace_id.to_string(),
            session_id: read_uuid(&arguments, "session_id")?,
            app: read_string(&arguments, "app")?,
        }),
        "app.quit" => Ok(HostRequest::QuitApp {
            trace_id: trace_id.to_string(),
            session_id: read_uuid(&arguments, "session_id")?,
            app: read_string(&arguments, "app")?,
        }),
        "window.list" => Ok(HostRequest::ListWindows {
            trace_id: trace_id.to_string(),
        }),
        "window.focus" => Ok(HostRequest::FocusWindow {
            trace_id: trace_id.to_string(),
            session_id: read_uuid(&arguments, "session_id")?,
            title: read_string(&arguments, "title")?,
        }),
        "window.move" => Ok(HostRequest::MoveWindow {
            trace_id: trace_id.to_string(),
            session_id: read_uuid(&arguments, "session_id")?,
            title: read_string(&arguments, "title")?,
            x: read_i32(&arguments, "x")?,
            y: read_i32(&arguments, "y")?,
        }),
        "window.resize" => Ok(HostRequest::ResizeWindow {
            trace_id: trace_id.to_string(),
            session_id: read_uuid(&arguments, "session_id")?,
            title: read_string(&arguments, "title")?,
            width: read_u32(&arguments, "width")?,
            height: read_u32(&arguments, "height")?,
        }),
        "observe.capture" => Ok(HostRequest::Capture {
            trace_id: trace_id.to_string(),
            screen: arguments
                .get("screen")
                .and_then(Value::as_str)
                .map(ToString::to_string),
        }),
        "ocr.read" => Ok(HostRequest::ReadOcr {
            trace_id: trace_id.to_string(),
            artifact_id: read_uuid(&arguments, "artifact_id")?,
        }),
        "vision.describe" => Ok(HostRequest::VisionDescribe {
            trace_id: trace_id.to_string(),
            artifact_id: read_uuid(&arguments, "artifact_id")?,
            prompt: arguments
                .get("prompt")
                .and_then(Value::as_str)
                .map(ToString::to_string),
        }),
        "vision.locate" => Ok(HostRequest::VisionLocate {
            trace_id: trace_id.to_string(),
            artifact_id: read_uuid(&arguments, "artifact_id")?,
            query: read_string(&arguments, "query")?,
        }),
        "input.click" => {
            let coordinates = if arguments.get("coordinates").is_some() {
                let payload = arguments
                    .get("coordinates")
                    .cloned()
                    .ok_or_else(|| anyhow!("coordinates were expected but missing"))?;
                Some(serde_json::from_value::<Coordinate>(payload)?)
            } else {
                None
            };

            Ok(HostRequest::Click {
                trace_id: trace_id.to_string(),
                session_id: read_uuid(&arguments, "session_id")?,
                target_ref: arguments
                    .get("target_ref")
                    .and_then(Value::as_str)
                    .map(Uuid::parse_str)
                    .transpose()?,
                coordinates,
            })
        }
        "input.type" => Ok(HostRequest::TypeText {
            trace_id: trace_id.to_string(),
            session_id: read_uuid(&arguments, "session_id")?,
            text: read_string(&arguments, "text")?,
        }),
        "input.hotkey" => Ok(HostRequest::Hotkey {
            trace_id: trace_id.to_string(),
            session_id: read_uuid(&arguments, "session_id")?,
            keys: serde_json::from_value(
                arguments
                    .get("keys")
                    .cloned()
                    .ok_or_else(|| anyhow!("missing keys"))?,
            )?,
        }),
        _ => Err(anyhow!("unknown tool: {name}")),
    }
}

fn summarize_response(response: &HostResponse) -> String {
    match response {
        HostResponse::Capabilities {
            platform,
            capabilities,
        } => format!(
            "{} capabilities reported for platform {}.",
            capabilities.len(),
            platform
        ),
        HostResponse::Permissions {
            platform,
            permissions,
        } => format!(
            "{} permission probes returned for platform {}.",
            permissions.len(),
            platform
        ),
        HostResponse::SessionOpened { session } => format!(
            "Session {} opened and expires at {}.",
            session.id, session.expires_at
        ),
        HostResponse::SessionClosed { session_id } => {
            format!("Session {session_id} has been closed.")
        }
        HostResponse::AppList { apps } => format!("{} application entries returned.", apps.len()),
        HostResponse::WindowList { windows } => {
            format!("{} window entries returned.", windows.len())
        }
        HostResponse::ArtifactCaptured { artifact } => format!(
            "Captured artifact {} with {} bytes.",
            artifact.id, artifact.bytes
        ),
        HostResponse::OcrRead { artifact_id, text } => format!(
            "OCR completed for artifact {} and produced {} characters.",
            artifact_id,
            text.chars().count()
        ),
        HostResponse::VisionDescription { artifact_id, .. } => {
            format!("Vision description returned for artifact {artifact_id}.")
        }
        HostResponse::VisionLocated { target } => {
            format!(
                "Vision located target {} at {:.2} confidence.",
                target.id, target.confidence
            )
        }
        HostResponse::ActionCompleted { message, .. } => message.clone(),
    }
}

fn read_string(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| anyhow!("missing string field: {field}"))
}

#[allow(dead_code)]
fn is_absolute_existing_file(path: &Path) -> bool {
    path.is_absolute() && path.is_file()
}

fn read_uuid(value: &Value, field: &str) -> Result<Uuid> {
    let raw = read_string(value, field)?;
    Ok(Uuid::parse_str(&raw)?)
}

fn read_i32(value: &Value, field: &str) -> Result<i32> {
    let raw = value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("missing integer field: {field}"))?;
    Ok(raw.try_into()?)
}

fn read_u32(value: &Value, field: &str) -> Result<u32> {
    let raw = value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing unsigned integer field: {field}"))?;
    Ok(raw.try_into()?)
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "desktop.capabilities",
            description: "List backend capabilities and current platform support.",
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "desktop.permissions",
            description: "Inspect local OS permissions required for desktop control.",
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "session.open",
            description: "Open a policy-bound automation session.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "capabilities": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "allowed_apps": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "allowed_windows": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "allowed_screens": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "allow_raw_input": { "type": "boolean" },
                    "dry_run": { "type": "boolean" },
                    "max_actions_per_minute": { "type": "integer", "minimum": 1 }
                },
                "required": ["capabilities"],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "session.close",
            description: "Close an existing automation session.",
            input_schema: schema_with_required(
                &["session_id"],
                json!({
                    "session_id": { "type": "string", "format": "uuid" }
                }),
            ),
        },
        ToolDefinition {
            name: "app.list",
            description: "List currently running applications.",
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "app.launch",
            description: "Launch an allowed desktop application.",
            input_schema: schema_with_required(
                &["session_id", "app"],
                json!({
                    "session_id": { "type": "string", "format": "uuid" },
                    "app": { "type": "string" }
                }),
            ),
        },
        ToolDefinition {
            name: "app.quit",
            description: "Request graceful quit for an allowed desktop application.",
            input_schema: schema_with_required(
                &["session_id", "app"],
                json!({
                    "session_id": { "type": "string", "format": "uuid" },
                    "app": { "type": "string" }
                }),
            ),
        },
        ToolDefinition {
            name: "window.list",
            description: "List visible desktop windows.",
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "window.focus",
            description: "Focus an allowed window by title.",
            input_schema: schema_with_required(
                &["session_id", "title"],
                json!({
                    "session_id": { "type": "string", "format": "uuid" },
                    "title": { "type": "string" }
                }),
            ),
        },
        ToolDefinition {
            name: "window.move",
            description: "Move an allowed window.",
            input_schema: schema_with_required(
                &["session_id", "title", "x", "y"],
                json!({
                    "session_id": { "type": "string", "format": "uuid" },
                    "title": { "type": "string" },
                    "x": { "type": "integer" },
                    "y": { "type": "integer" }
                }),
            ),
        },
        ToolDefinition {
            name: "window.resize",
            description: "Resize an allowed window.",
            input_schema: schema_with_required(
                &["session_id", "title", "width", "height"],
                json!({
                    "session_id": { "type": "string", "format": "uuid" },
                    "title": { "type": "string" },
                    "width": { "type": "integer", "minimum": 1 },
                    "height": { "type": "integer", "minimum": 1 }
                }),
            ),
        },
        ToolDefinition {
            name: "observe.capture",
            description: "Capture a screenshot artifact from the local desktop.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "screen": { "type": "string" }
                },
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "ocr.read",
            description: "Run OCR against a captured artifact.",
            input_schema: schema_with_required(
                &["artifact_id"],
                json!({
                    "artifact_id": { "type": "string", "format": "uuid" }
                }),
            ),
        },
        ToolDefinition {
            name: "vision.describe",
            description: "Describe a captured artifact using a configured vision provider.",
            input_schema: schema_with_required(
                &["artifact_id"],
                json!({
                    "artifact_id": { "type": "string", "format": "uuid" },
                    "prompt": { "type": "string" }
                }),
            ),
        },
        ToolDefinition {
            name: "vision.locate",
            description: "Locate a target within a captured artifact using vision.",
            input_schema: schema_with_required(
                &["artifact_id", "query"],
                json!({
                    "artifact_id": { "type": "string", "format": "uuid" },
                    "query": { "type": "string" }
                }),
            ),
        },
        ToolDefinition {
            name: "input.click",
            description: "Click an on-screen target or explicit coordinates.",
            input_schema: schema_with_required(
                &["session_id"],
                json!({
                    "session_id": { "type": "string", "format": "uuid" },
                    "target_ref": { "type": "string", "format": "uuid" },
                    "coordinates": {
                        "type": "object",
                        "properties": {
                            "x": { "type": "integer" },
                            "y": { "type": "integer" }
                        },
                        "required": ["x", "y"],
                        "additionalProperties": false
                    }
                }),
            ),
        },
        ToolDefinition {
            name: "input.type",
            description: "Type text into the currently focused surface.",
            input_schema: schema_with_required(
                &["session_id", "text"],
                json!({
                    "session_id": { "type": "string", "format": "uuid" },
                    "text": { "type": "string" }
                }),
            ),
        },
        ToolDefinition {
            name: "input.hotkey",
            description: "Send a hotkey combination.",
            input_schema: schema_with_required(
                &["session_id", "keys"],
                json!({
                    "session_id": { "type": "string", "format": "uuid" },
                    "keys": {
                        "type": "array",
                        "items": { "type": "string" },
                        "minItems": 1
                    }
                }),
            ),
        },
    ]
}

fn schema_with_required(required: &[&str], properties: Value) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}
