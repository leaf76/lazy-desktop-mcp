use anyhow::{Context, Result};
use chrono::Duration;
use desktop_core::{
    AppDescriptor, AuditEvent, BackendCapability, BoundingBox, Capability, Coordinate, HostRequest,
    HostResponse, ObservationArtifact, PermissionState, PermissionStatus, PolicyEngine, Session,
    SessionPolicy, ToolError, VisionTarget, WindowDescriptor,
};
use directories::ProjectDirs;
use enigo::{
    Button, Coordinate as InputCoordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings,
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration as StdDuration;
use sysinfo::{ProcessesToUpdate, System};
use uuid::Uuid;
use wait_timeout::ChildExt;

const COMMAND_TIMEOUT_SECS: u64 = 10;
const APPROVAL_DIALOG_TIMEOUT_SECS: u64 = 30;
const DEFAULT_SESSION_TTL_MINUTES: i64 = 15;
const DEFAULT_MAX_ACTIONS_PER_MINUTE: usize = 30;
const POLICY_PATH_ENV_VAR: &str = "LAZY_DESKTOP_POLICY_PATH";
const OVERLAY_POLICY_FILE_NAME: &str = "policy-overlay.json";
const ACCESSIBILITY_PERMISSION_REASON: &str =
    "Accessibility permission is required for window and input automation.";
const SCREEN_RECORDING_PERMISSION_REASON: &str =
    "Screen Recording permission is required for screenshot-driven automation.";
const VISION_COMMAND_ENV_VAR: &str = "LAZY_DESKTOP_VISION_COMMAND";
const VISION_ARGS_ENV_VAR: &str = "LAZY_DESKTOP_VISION_ARGS";
const VISION_TARGET_TTL_MINUTES: i64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HostSecurityPolicy {
    pub allowed_standalone_capabilities: BTreeSet<Capability>,
    pub allowed_session_capabilities: BTreeSet<Capability>,
    pub allowed_apps: Vec<String>,
    pub allowed_windows: Vec<String>,
    pub allowed_screens: Vec<String>,
    pub allow_raw_input: bool,
    pub max_actions_per_minute: usize,
}

impl Default for HostSecurityPolicy {
    fn default() -> Self {
        Self {
            allowed_standalone_capabilities: BTreeSet::new(),
            allowed_session_capabilities: BTreeSet::new(),
            allowed_apps: Vec::new(),
            allowed_windows: Vec::new(),
            allowed_screens: Vec::new(),
            allow_raw_input: false,
            max_actions_per_minute: DEFAULT_MAX_ACTIONS_PER_MINUTE,
        }
    }
}

impl HostSecurityPolicy {
    fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read host policy {}", path.display()))?;
        serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse host policy {}", path.display()))
    }

    pub fn for_test() -> Self {
        Self {
            allowed_standalone_capabilities: BTreeSet::from([
                Capability::AppList,
                Capability::WindowList,
                Capability::ObserveCapture,
                Capability::OcrRead,
                Capability::VisionDescribe,
                Capability::VisionLocate,
            ]),
            allowed_session_capabilities: BTreeSet::from([
                Capability::AppLaunch,
                Capability::AppQuit,
                Capability::WindowFocus,
                Capability::WindowMove,
                Capability::WindowResize,
                Capability::InputClick,
                Capability::InputType,
                Capability::InputHotkey,
            ]),
            allowed_apps: vec!["TextEdit".to_string()],
            allowed_windows: vec!["Editor".to_string()],
            allowed_screens: vec!["primary".to_string()],
            allow_raw_input: false,
            max_actions_per_minute: 60,
        }
    }

    fn merged_with_overlay(&self, overlay: &ScopeOverlayPolicy) -> Self {
        let mut merged = self.clone();
        merged.allowed_apps = merge_scope_values(&merged.allowed_apps, &overlay.allowed_apps);
        merged.allowed_windows =
            merge_scope_values(&merged.allowed_windows, &overlay.allowed_windows);
        merged.allowed_screens =
            merge_scope_values(&merged.allowed_screens, &overlay.allowed_screens);
        merged
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScopeOverlayPolicy {
    pub allowed_apps: Vec<String>,
    pub allowed_windows: Vec<String>,
    pub allowed_screens: Vec<String>,
}

impl ScopeOverlayPolicy {
    fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read overlay policy {}", path.display()))?;
        serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse overlay policy {}", path.display()))
    }

    fn persist(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create overlay directory {}", parent.display())
            })?;
        }

        let temp_path = path.with_extension("json.tmp");
        let contents = serde_json::to_vec_pretty(self)?;
        std::fs::write(&temp_path, contents)
            .with_context(|| format!("failed to write overlay policy {}", temp_path.display()))?;
        std::fs::rename(&temp_path, path).with_context(|| {
            format!(
                "failed to replace overlay policy {} with {}",
                path.display(),
                temp_path.display()
            )
        })?;
        Ok(())
    }

    fn add_target(&mut self, target_kind: ApprovalTargetKind, target_value: &str) -> bool {
        let targets = match target_kind {
            ApprovalTargetKind::App => &mut self.allowed_apps,
            ApprovalTargetKind::Window => &mut self.allowed_windows,
            ApprovalTargetKind::Screen => &mut self.allowed_screens,
        };

        if targets.iter().any(|item| item == target_value) {
            return false;
        }

        targets.push(target_value.to_string());
        targets.sort();
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalTargetKind {
    App,
    Window,
    Screen,
}

impl ApprovalTargetKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Window => "window",
            Self::Screen => "screen",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    AllowPersist,
    Deny,
    TimedOut,
}

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub capability: Capability,
    pub target_kind: ApprovalTargetKind,
    pub target_value: String,
    pub session_id: Option<Uuid>,
    pub trace_id: String,
}

pub trait ApprovalBroker: Send + Sync {
    fn request(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ToolError>;
}

enum ApprovalFlowResult {
    Applied,
    Skipped,
    Denied(ToolError),
}

struct ApprovalAudit<'a> {
    capability: Capability,
    session_id: Option<Uuid>,
    target_kind: ApprovalTargetKind,
    target_value: &'a str,
    decision: &'a str,
    persisted: bool,
}

#[derive(Debug, Clone)]
pub struct HostServiceConfig {
    pub audit_db_path: PathBuf,
    pub artifact_dir: PathBuf,
    pub session_ttl: Duration,
    pub base_security_policy: HostSecurityPolicy,
    pub security_policy: HostSecurityPolicy,
    pub security_policy_path: PathBuf,
    pub overlay_policy: ScopeOverlayPolicy,
    pub overlay_policy_path: PathBuf,
    pub vision_command: Option<VisionCommandConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisionCommandConfig {
    pub command: String,
    pub args: Vec<String>,
}

impl HostServiceConfig {
    pub fn load() -> Result<Self> {
        let project_dirs = ProjectDirs::from("dev", "lazy", "desktop-mcp")
            .context("unable to resolve application data directory")?;
        let data_dir = project_dirs.data_local_dir();
        let security_policy_path = std::env::var_os(POLICY_PATH_ENV_VAR)
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("policy.json"));
        let overlay_policy_path = data_dir.join(OVERLAY_POLICY_FILE_NAME);
        let base_security_policy = HostSecurityPolicy::load(&security_policy_path)?;
        let overlay_policy = ScopeOverlayPolicy::load(&overlay_policy_path)?;

        Ok(Self {
            audit_db_path: data_dir.join("audit.db"),
            artifact_dir: data_dir.join("artifacts"),
            session_ttl: Duration::minutes(DEFAULT_SESSION_TTL_MINUTES),
            base_security_policy: base_security_policy.clone(),
            security_policy: base_security_policy.merged_with_overlay(&overlay_policy),
            security_policy_path,
            overlay_policy,
            overlay_policy_path,
            vision_command: load_vision_command_config()?,
        })
    }

    pub fn for_test(root: &Path) -> Self {
        let base_security_policy = HostSecurityPolicy::for_test();
        Self {
            audit_db_path: root.join("audit.db"),
            artifact_dir: root.join("artifacts"),
            session_ttl: Duration::minutes(DEFAULT_SESSION_TTL_MINUTES),
            base_security_policy: base_security_policy.clone(),
            security_policy: base_security_policy,
            security_policy_path: root.join("policy.json"),
            overlay_policy: ScopeOverlayPolicy::default(),
            overlay_policy_path: root.join(OVERLAY_POLICY_FILE_NAME),
            vision_command: None,
        }
    }

    pub fn with_security_policy(mut self, security_policy: HostSecurityPolicy) -> Self {
        self.base_security_policy = security_policy.clone();
        self.security_policy = security_policy;
        self
    }

    pub fn with_vision_command(mut self, command: impl Into<String>, args: Vec<String>) -> Self {
        self.vision_command = Some(VisionCommandConfig {
            command: command.into(),
            args,
        });
        self
    }
}

fn merge_scope_values(base: &[String], overlay: &[String]) -> Vec<String> {
    base.iter()
        .chain(overlay.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

struct SqliteAuditStore {
    connection: Connection,
}

impl SqliteAuditStore {
    fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create audit directory: {}", parent.display())
            })?;
        }

        let connection =
            Connection::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                capability TEXT NOT NULL,
                decision TEXT NOT NULL,
                session_id TEXT,
                payload_kind TEXT NOT NULL,
                payload_preview TEXT,
                payload_sha256 TEXT
            );",
        )?;

        Ok(Self { connection })
    }

    fn append(&self, event: &AuditEvent) -> Result<()> {
        self.connection.execute(
            "INSERT INTO audit_events (
                id,
                trace_id,
                timestamp,
                capability,
                decision,
                session_id,
                payload_kind,
                payload_preview,
                payload_sha256
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                event.id.to_string(),
                event.trace_id,
                event.timestamp.to_rfc3339(),
                event.capability.tool_name(),
                event.decision,
                event.session_id.map(|value| value.to_string()),
                serde_json::to_string(&event.payload.kind)?,
                event.payload.preview,
                event.payload.sha256,
            ],
        )?;

        Ok(())
    }
}

pub trait VisionAdapter: Send + Sync {
    fn describe(
        &self,
        _artifact: &ObservationArtifact,
        trace_id: &str,
    ) -> Result<String, ToolError> {
        Err(ToolError::unsupported(
            "Vision description is not configured.",
            trace_id,
        ))
    }

    fn locate(
        &self,
        _artifact: &ObservationArtifact,
        _query: &str,
        trace_id: &str,
    ) -> Result<VisionTarget, ToolError> {
        Err(ToolError::unsupported(
            "Vision locate is not configured.",
            trace_id,
        ))
    }
}

#[derive(Debug, Default)]
pub struct DisabledVisionAdapter;

impl VisionAdapter for DisabledVisionAdapter {}

#[derive(Debug)]
struct CliVisionAdapter {
    command: String,
    args: Vec<String>,
}

impl CliVisionAdapter {
    fn new(command: String, args: Vec<String>) -> Self {
        Self { command, args }
    }
}

impl VisionAdapter for CliVisionAdapter {
    fn describe(
        &self,
        artifact: &ObservationArtifact,
        trace_id: &str,
    ) -> Result<String, ToolError> {
        let response = invoke_vision_adapter(
            &self.command,
            &self.args,
            &json!({
                "action": "describe",
                "artifact": {
                    "id": artifact.id,
                    "path": artifact.path,
                    "mime_type": artifact.mime_type,
                    "sha256": artifact.sha256,
                }
            }),
            trace_id,
        )?;
        response
            .get("summary")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .ok_or_else(|| {
                ToolError::internal("Vision adapter did not return a `summary` field.", trace_id)
            })
    }

    fn locate(
        &self,
        artifact: &ObservationArtifact,
        query: &str,
        trace_id: &str,
    ) -> Result<VisionTarget, ToolError> {
        #[derive(Deserialize)]
        struct VisionLocatePayload {
            target: VisionLocateTarget,
        }

        #[derive(Deserialize)]
        struct VisionLocateTarget {
            label: String,
            bbox: BoundingBox,
            confidence: f32,
        }

        let response = invoke_vision_adapter(
            &self.command,
            &self.args,
            &json!({
                "action": "locate",
                "query": query,
                "artifact": {
                    "id": artifact.id,
                    "path": artifact.path,
                    "mime_type": artifact.mime_type,
                    "sha256": artifact.sha256,
                }
            }),
            trace_id,
        )?;
        let payload: VisionLocatePayload = serde_json::from_value(response).map_err(|error| {
            ToolError::internal(
                format!("Vision adapter returned an invalid locate payload: {error}"),
                trace_id,
            )
        })?;

        Ok(VisionTarget {
            id: Uuid::new_v4(),
            label: payload.target.label,
            bbox: payload.target.bbox,
            confidence: payload.target.confidence,
            artifact_id: artifact.id,
            expires_at: chrono::Utc::now() + Duration::minutes(VISION_TARGET_TTL_MINUTES),
        })
    }
}

struct MacOsApprovalBroker;

impl ApprovalBroker for MacOsApprovalBroker {
    fn request(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ToolError> {
        let title = apple_script_string("lazy-desktop-mcp approval");
        let message = apple_script_string(&format!(
            "Codex requested {} access for {} '{}'.\nIf you allow this request, the target will be added to the local overlay policy and future requests will not prompt again.",
            request.capability.tool_name(),
            request.target_kind.as_str(),
            request.target_value,
        ));
        let script = format!(
            "set response to display dialog {message} with title {title} buttons {{\"Deny\", \"Allow\"}} default button \"Allow\" cancel button \"Deny\" giving up after {timeout}\n\
             if gave up of response then\n\
                 return \"TIMEOUT\"\n\
             end if\n\
             return button returned of response",
            timeout = APPROVAL_DIALOG_TIMEOUT_SECS,
        );

        let mut command = Command::new("/usr/bin/osascript");
        command.arg("-e").arg(script);

        let (status, stdout, stderr) = wait_for_command_output(
            &mut command,
            StdDuration::from_secs(APPROVAL_DIALOG_TIMEOUT_SECS + 5),
            "Approval dialog",
            &request.trace_id,
        )?;

        if !status.success() {
            if stderr.contains("User canceled") {
                return Ok(ApprovalDecision::Deny);
            }

            return Err(ToolError::internal(
                format!("Approval dialog failed: {stderr}"),
                &request.trace_id,
            ));
        }

        match stdout.trim() {
            "Allow" => Ok(ApprovalDecision::AllowPersist),
            "Deny" => Ok(ApprovalDecision::Deny),
            "TIMEOUT" => Ok(ApprovalDecision::TimedOut),
            other => Err(ToolError::internal(
                format!("Approval dialog returned an unexpected result: {other}"),
                &request.trace_id,
            )),
        }
    }
}

pub trait PlatformBackend {
    fn platform_name(&self) -> &'static str;
    fn capabilities(&self) -> Vec<BackendCapability>;
    fn permission_statuses(&self) -> Vec<PermissionStatus>;

    fn list_apps(&mut self, trace_id: &str) -> Result<Vec<AppDescriptor>, ToolError>;

    fn launch_app(&mut self, _app: &str, trace_id: &str) -> Result<String, ToolError> {
        Err(ToolError::unsupported(
            "App launch is not supported by this backend.",
            trace_id,
        ))
    }

    fn quit_app(&mut self, _app: &str, trace_id: &str) -> Result<String, ToolError> {
        Err(ToolError::unsupported(
            "App quit is not supported by this backend.",
            trace_id,
        ))
    }

    fn list_windows(&mut self, trace_id: &str) -> Result<Vec<WindowDescriptor>, ToolError> {
        Err(ToolError::unsupported(
            "Window enumeration is not supported by this backend.",
            trace_id,
        ))
    }

    fn focus_window(&mut self, _title: &str, trace_id: &str) -> Result<String, ToolError> {
        Err(ToolError::unsupported(
            "Window focus is not supported by this backend.",
            trace_id,
        ))
    }

    fn move_window(
        &mut self,
        _title: &str,
        _coordinate: Coordinate,
        trace_id: &str,
    ) -> Result<String, ToolError> {
        Err(ToolError::unsupported(
            "Window move is not supported by this backend.",
            trace_id,
        ))
    }

    fn resize_window(
        &mut self,
        _title: &str,
        _width: u32,
        _height: u32,
        trace_id: &str,
    ) -> Result<String, ToolError> {
        Err(ToolError::unsupported(
            "Window resize is not supported by this backend.",
            trace_id,
        ))
    }

    fn capture(
        &mut self,
        _screen: Option<&str>,
        _output_path: &Path,
        trace_id: &str,
    ) -> Result<(), ToolError> {
        Err(ToolError::unsupported(
            "Screenshot capture is not supported by this backend.",
            trace_id,
        ))
    }

    fn read_ocr(&mut self, _artifact_path: &Path, trace_id: &str) -> Result<String, ToolError> {
        Err(ToolError::unsupported(
            "OCR is not supported by this backend.",
            trace_id,
        ))
    }

    fn click(&mut self, _coordinate: Coordinate, trace_id: &str) -> Result<String, ToolError> {
        Err(ToolError::unsupported(
            "Mouse input is not supported by this backend.",
            trace_id,
        ))
    }

    fn type_text(&mut self, _text: &str, trace_id: &str) -> Result<String, ToolError> {
        Err(ToolError::unsupported(
            "Keyboard text input is not supported by this backend.",
            trace_id,
        ))
    }

    fn hotkey(&mut self, _keys: &[String], trace_id: &str) -> Result<String, ToolError> {
        Err(ToolError::unsupported(
            "Keyboard hotkeys are not supported by this backend.",
            trace_id,
        ))
    }
}

#[derive(Debug, Default)]
pub struct SystemPlatformBackend;

impl PlatformBackend for SystemPlatformBackend {
    fn platform_name(&self) -> &'static str {
        std::env::consts::OS
    }

    fn capabilities(&self) -> Vec<BackendCapability> {
        system_backend_capabilities(
            std::env::consts::OS,
            probe_accessibility_permission(),
            probe_screen_recording_permission(),
            command_exists("tesseract"),
            vision_provider_configured(),
        )
    }

    fn permission_statuses(&self) -> Vec<PermissionStatus> {
        system_permission_statuses(
            std::env::consts::OS,
            probe_accessibility_permission(),
            probe_screen_recording_permission(),
        )
    }

    fn list_apps(&mut self, trace_id: &str) -> Result<Vec<AppDescriptor>, ToolError> {
        let mut system = System::new_all();
        system.refresh_processes(ProcessesToUpdate::All, true);

        let mut apps = BTreeMap::new();
        for process in system.processes().values() {
            let name = process.name().to_string_lossy().into_owned();
            apps.entry(name).or_insert(process.pid().as_u32());
        }

        if apps.is_empty() {
            return Err(ToolError::not_found(
                "No running desktop applications could be enumerated.",
                trace_id,
            ));
        }

        Ok(apps
            .into_iter()
            .map(|(name, pid)| AppDescriptor {
                name,
                pid: Some(pid),
            })
            .collect())
    }

    fn launch_app(&mut self, app: &str, trace_id: &str) -> Result<String, ToolError> {
        let mut command = match std::env::consts::OS {
            "macos" => {
                let mut command = Command::new("open");
                command.arg("-a").arg(app);
                command
            }
            "windows" => {
                let mut command = Command::new("cmd");
                command.args(["/C", "start", "", app]);
                command
            }
            _ => {
                let mut command = Command::new("gtk-launch");
                command.arg(app);
                command
            }
        };

        wait_for_command_success(
            &mut command,
            StdDuration::from_secs(COMMAND_TIMEOUT_SECS),
            &format!("Launch request for {app}"),
            trace_id,
        )?;
        Ok(format!("Launch request submitted for {app}."))
    }

    fn list_windows(&mut self, trace_id: &str) -> Result<Vec<WindowDescriptor>, ToolError> {
        match std::env::consts::OS {
            "macos" => {
                let script = r#"
tell application "System Events"
    set output to {}
    repeat with proc in application processes
        repeat with win in windows of proc
            try
                set end of output to (name of proc as text) & tab & (name of win as text) & tab & ((item 1 of position of win) as text) & tab & ((item 2 of position of win) as text) & tab & ((item 1 of size of win) as text) & tab & ((item 2 of size of win) as text)
            end try
        end repeat
    end repeat
    set AppleScript's text item delimiters to linefeed
    return output as text
end tell
"#;
                let output = run_macos_apple_script(script, "Window enumeration", trace_id)?;
                Ok(parse_macos_window_list(&output))
            }
            _ => Err(ToolError::unsupported(
                "Window enumeration is not supported by this platform backend.",
                trace_id,
            )),
        }
    }

    fn focus_window(&mut self, title: &str, trace_id: &str) -> Result<String, ToolError> {
        match std::env::consts::OS {
            "macos" => {
                let target = apple_script_string(title);
                let script = format!(
                    r#"
tell application "System Events"
    repeat with proc in application processes
        repeat with win in windows of proc
            try
                if (name of win as text) is equal to {target} then
                    set frontmost of proc to true
                    try
                        perform action "AXRaise" of win
                    end try
                    return name of proc as text
                end if
            end try
        end repeat
    end repeat
end tell
error "WINDOW_NOT_FOUND"
"#
                );
                let app_name = run_macos_apple_script(&script, "Window focus", trace_id)?;
                Ok(format!(
                    "Focused window {title} for application {}.",
                    app_name.trim()
                ))
            }
            _ => Err(ToolError::unsupported(
                "Window focus is not supported by this platform backend.",
                trace_id,
            )),
        }
    }

    fn move_window(
        &mut self,
        title: &str,
        coordinate: Coordinate,
        trace_id: &str,
    ) -> Result<String, ToolError> {
        match std::env::consts::OS {
            "macos" => {
                let target = apple_script_string(title);
                let script = format!(
                    r#"
tell application "System Events"
    repeat with proc in application processes
        repeat with win in windows of proc
            try
                if (name of win as text) is equal to {target} then
                    set position of win to {{{x}, {y}}}
                    return name of proc as text
                end if
            end try
        end repeat
    end repeat
end tell
error "WINDOW_NOT_FOUND"
"#,
                    x = coordinate.x,
                    y = coordinate.y,
                );
                let app_name = run_macos_apple_script(&script, "Window move", trace_id)?;
                Ok(format!(
                    "Moved window {title} for application {} to ({}, {}).",
                    app_name.trim(),
                    coordinate.x,
                    coordinate.y
                ))
            }
            _ => Err(ToolError::unsupported(
                "Window move is not supported by this platform backend.",
                trace_id,
            )),
        }
    }

    fn resize_window(
        &mut self,
        title: &str,
        width: u32,
        height: u32,
        trace_id: &str,
    ) -> Result<String, ToolError> {
        match std::env::consts::OS {
            "macos" => {
                let target = apple_script_string(title);
                let script = format!(
                    r#"
tell application "System Events"
    repeat with proc in application processes
        repeat with win in windows of proc
            try
                if (name of win as text) is equal to {target} then
                    set size of win to {{{width}, {height}}}
                    return name of proc as text
                end if
            end try
        end repeat
    end repeat
end tell
error "WINDOW_NOT_FOUND"
"#
                );
                let app_name = run_macos_apple_script(&script, "Window resize", trace_id)?;
                Ok(format!(
                    "Resized window {title} for application {} to {}x{}.",
                    app_name.trim(),
                    width,
                    height
                ))
            }
            _ => Err(ToolError::unsupported(
                "Window resize is not supported by this platform backend.",
                trace_id,
            )),
        }
    }

    fn capture(
        &mut self,
        screen: Option<&str>,
        output_path: &Path,
        trace_id: &str,
    ) -> Result<(), ToolError> {
        if let Some(screen) = screen
            && screen != "primary"
        {
            return Err(ToolError::unsupported(
                "The current screenshot backend only supports the primary display.",
                trace_id,
            ));
        }

        let timeout = StdDuration::from_secs(COMMAND_TIMEOUT_SECS);
        match std::env::consts::OS {
            "macos" => {
                let mut command = Command::new("screencapture");
                command.arg("-x").arg(output_path);
                wait_for_command_success(&mut command, timeout, "Screenshot capture", trace_id)
            }
            "windows" => {
                let script = format!(
                    "Add-Type -AssemblyName System.Windows.Forms; \
                     Add-Type -AssemblyName System.Drawing; \
                     $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; \
                     $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height; \
                     $graphics = [System.Drawing.Graphics]::FromImage($bitmap); \
                     $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size); \
                     $bitmap.Save('{}', [System.Drawing.Imaging.ImageFormat]::Png); \
                     $graphics.Dispose(); \
                     $bitmap.Dispose();",
                    output_path.display().to_string().replace('\'', "''")
                );
                let mut command = Command::new("powershell");
                command
                    .arg("-NoProfile")
                    .arg("-NonInteractive")
                    .arg("-Command")
                    .arg(script);
                wait_for_command_success(&mut command, timeout, "Screenshot capture", trace_id)
            }
            _ => {
                let mut gnome_screenshot = Command::new("gnome-screenshot");
                gnome_screenshot.arg("-f").arg(output_path);
                if wait_for_command_success(
                    &mut gnome_screenshot,
                    timeout,
                    "Screenshot capture",
                    trace_id,
                )
                .is_ok()
                {
                    return Ok(());
                }

                let mut grim = Command::new("grim");
                grim.arg(output_path);
                if wait_for_command_success(&mut grim, timeout, "Screenshot capture", trace_id)
                    .is_ok()
                {
                    return Ok(());
                }

                Err(ToolError::unsupported(
                    "Screenshot capture requires `gnome-screenshot` or `grim` on this platform.",
                    trace_id,
                ))
            }
        }
    }

    fn read_ocr(&mut self, artifact_path: &Path, trace_id: &str) -> Result<String, ToolError> {
        let mut command = Command::new("tesseract");
        command.arg(artifact_path).arg("stdout");
        capture_command_stdout(
            &mut command,
            StdDuration::from_secs(COMMAND_TIMEOUT_SECS),
            "OCR command",
            trace_id,
        )
        .map(|text| text.trim().to_string())
        .map_err(|error| {
            if error.message.contains("No such file or directory") {
                ToolError::unsupported(
                    "OCR requires the `tesseract` binary to be installed and available on PATH.",
                    trace_id,
                )
            } else {
                error
            }
        })
    }

    fn click(&mut self, coordinate: Coordinate, trace_id: &str) -> Result<String, ToolError> {
        let mut enigo = new_enigo(trace_id)?;
        enigo
            .move_mouse(coordinate.x, coordinate.y, InputCoordinate::Abs)
            .map_err(|error| {
                ToolError::internal(format!("Mouse move failed: {error}"), trace_id)
            })?;
        enigo
            .button(Button::Left, Direction::Click)
            .map_err(|error| {
                ToolError::internal(format!("Mouse click failed: {error}"), trace_id)
            })?;
        Ok(format!("Clicked at ({}, {}).", coordinate.x, coordinate.y))
    }

    fn type_text(&mut self, text: &str, trace_id: &str) -> Result<String, ToolError> {
        let mut enigo = new_enigo(trace_id)?;
        enigo.text(text).map_err(|error| {
            ToolError::internal(format!("Text input failed: {error}"), trace_id)
        })?;
        Ok(format!(
            "Typed {} characters into the active window.",
            text.chars().count()
        ))
    }

    fn hotkey(&mut self, keys: &[String], trace_id: &str) -> Result<String, ToolError> {
        let mut enigo = new_enigo(trace_id)?;
        let parsed_keys = keys
            .iter()
            .map(|value| parse_hotkey_key(value, trace_id))
            .collect::<Result<Vec<_>, _>>()?;
        let (last_key, modifiers) = parsed_keys.split_last().ok_or_else(|| {
            ToolError::validation("At least one hotkey key is required.", trace_id)
        })?;

        for modifier in modifiers {
            enigo.key(*modifier, Direction::Press).map_err(|error| {
                ToolError::internal(format!("Hotkey press failed: {error}"), trace_id)
            })?;
        }
        enigo.key(*last_key, Direction::Click).map_err(|error| {
            ToolError::internal(format!("Hotkey send failed: {error}"), trace_id)
        })?;
        for modifier in modifiers.iter().rev() {
            enigo.key(*modifier, Direction::Release).map_err(|error| {
                ToolError::internal(format!("Hotkey release failed: {error}"), trace_id)
            })?;
        }

        Ok(format!("Sent hotkey {}.", keys.join("+")))
    }
}

#[derive(Debug, Default)]
pub struct FakePlatformBackend {
    launched_apps: Vec<String>,
}

impl PlatformBackend for FakePlatformBackend {
    fn platform_name(&self) -> &'static str {
        "test"
    }

    fn capabilities(&self) -> Vec<BackendCapability> {
        vec![
            BackendCapability {
                capability: Capability::AppList,
                supported: true,
                reason: None,
            },
            BackendCapability {
                capability: Capability::AppLaunch,
                supported: true,
                reason: None,
            },
            BackendCapability {
                capability: Capability::WindowList,
                supported: true,
                reason: None,
            },
            BackendCapability {
                capability: Capability::WindowFocus,
                supported: true,
                reason: None,
            },
            BackendCapability {
                capability: Capability::InputClick,
                supported: true,
                reason: None,
            },
            BackendCapability {
                capability: Capability::InputType,
                supported: true,
                reason: None,
            },
            BackendCapability {
                capability: Capability::InputHotkey,
                supported: true,
                reason: None,
            },
        ]
    }

    fn permission_statuses(&self) -> Vec<PermissionStatus> {
        vec![PermissionStatus {
            name: "test_mode".to_string(),
            state: PermissionState::Granted,
            required_for: vec![
                Capability::AppLaunch,
                Capability::WindowFocus,
                Capability::InputClick,
                Capability::InputType,
                Capability::InputHotkey,
            ],
            details: "The fake backend allows deterministic host service tests.".to_string(),
        }]
    }

    fn list_apps(&mut self, _trace_id: &str) -> Result<Vec<AppDescriptor>, ToolError> {
        Ok(self
            .launched_apps
            .iter()
            .map(|app| AppDescriptor {
                name: app.clone(),
                pid: Some(1),
            })
            .collect())
    }

    fn launch_app(&mut self, app: &str, _trace_id: &str) -> Result<String, ToolError> {
        self.launched_apps.push(app.to_string());
        Ok(format!("Launch request submitted for {app}."))
    }

    fn list_windows(&mut self, _trace_id: &str) -> Result<Vec<WindowDescriptor>, ToolError> {
        Ok(vec![WindowDescriptor {
            id: "test-window-1".to_string(),
            title: "Editor".to_string(),
            app_name: Some("TextEdit".to_string()),
            position: Some(Coordinate { x: 10, y: 10 }),
            size: Some(desktop_core::Size {
                width: 1280,
                height: 720,
            }),
        }])
    }

    fn focus_window(&mut self, title: &str, _trace_id: &str) -> Result<String, ToolError> {
        Ok(format!("Focused window {title}."))
    }

    fn click(&mut self, coordinate: Coordinate, _trace_id: &str) -> Result<String, ToolError> {
        Ok(format!("Clicked at ({}, {}).", coordinate.x, coordinate.y))
    }

    fn type_text(&mut self, text: &str, _trace_id: &str) -> Result<String, ToolError> {
        Ok(format!(
            "Typed {} characters into the active window.",
            text.chars().count()
        ))
    }

    fn hotkey(&mut self, keys: &[String], _trace_id: &str) -> Result<String, ToolError> {
        Ok(format!("Sent hotkey {}.", keys.join("+")))
    }
}

pub struct HostService<B: PlatformBackend> {
    backend: B,
    policy_engine: PolicyEngine,
    audit_store: SqliteAuditStore,
    sessions: HashMap<Uuid, Session>,
    artifacts: HashMap<Uuid, ObservationArtifact>,
    vision_targets: HashMap<Uuid, VisionTarget>,
    config: HostServiceConfig,
    vision: Box<dyn VisionAdapter>,
    approval: Option<Box<dyn ApprovalBroker>>,
}

impl<B: PlatformBackend> HostService<B> {
    pub async fn new(backend: B, config: HostServiceConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.artifact_dir).with_context(|| {
            format!(
                "failed to create artifact directory {}",
                config.artifact_dir.display()
            )
        })?;
        let audit_store = SqliteAuditStore::open(&config.audit_db_path)?;
        let approval = default_approval_broker(backend.platform_name());
        let vision = build_vision_adapter(&config);

        Ok(Self {
            backend,
            policy_engine: PolicyEngine::default(),
            audit_store,
            sessions: HashMap::new(),
            artifacts: HashMap::new(),
            vision_targets: HashMap::new(),
            config,
            vision,
            approval,
        })
    }

    pub fn with_approval_broker<A>(mut self, approval: A) -> Self
    where
        A: ApprovalBroker + 'static,
    {
        self.approval = Some(Box::new(approval));
        self
    }

    pub async fn handle(&mut self, request: HostRequest) -> Result<HostResponse, ToolError> {
        let trace_id = request.trace_id().to_string();
        let capability = request.capability();
        let session_id = request.session_id();
        let payload = request.audit_payload();
        let result = self.handle_inner(request).await;

        let decision = if result.is_ok() { "allowed" } else { "denied" };
        let audit_event =
            AuditEvent::new(trace_id.clone(), capability, decision, session_id, payload);
        self.append_audit_event(&audit_event, &trace_id)?;

        match result {
            Ok(HostResponse::ActionCompleted { message, .. }) => {
                Ok(HostResponse::ActionCompleted {
                    trace_id,
                    audit_event_id: audit_event.id,
                    message,
                })
            }
            Ok(response) => Ok(response),
            Err(error) => Err(error),
        }
    }

    async fn handle_inner(&mut self, request: HostRequest) -> Result<HostResponse, ToolError> {
        match request {
            HostRequest::GetCapabilities { .. } => Ok(HostResponse::Capabilities {
                platform: self.backend.platform_name().to_string(),
                capabilities: self.effective_capabilities(),
            }),
            HostRequest::GetPermissions { .. } => Ok(HostResponse::Permissions {
                platform: self.backend.platform_name().to_string(),
                permissions: self.backend.permission_statuses(),
            }),
            HostRequest::OpenSession { trace_id, policy } => {
                let policy = self.constrain_session_policy(policy, &trace_id)?;
                let session = Session::new(policy, self.config.session_ttl);
                self.sessions.insert(session.id, session.clone());
                Ok(HostResponse::SessionOpened { session })
            }
            HostRequest::CloseSession {
                trace_id,
                session_id,
            } => {
                self.sessions.remove(&session_id).ok_or_else(|| {
                    ToolError::not_found("The requested session does not exist.", &trace_id)
                })?;
                Ok(HostResponse::SessionClosed { session_id })
            }
            HostRequest::ListApps { trace_id } => {
                self.authorize_standalone_capability(Capability::AppList, &trace_id)?;
                Ok(HostResponse::AppList {
                    apps: self.backend.list_apps(&trace_id)?,
                })
            }
            HostRequest::LaunchApp {
                trace_id,
                session_id,
                app,
            } => {
                let request = HostRequest::LaunchApp {
                    trace_id: trace_id.clone(),
                    session_id,
                    app: app.clone(),
                };
                self.authorize_or_approve_request(session_id, &request)?;
                let message = if self.is_dry_run(session_id, &trace_id)? {
                    "Dry-run policy prevented the action from executing.".to_string()
                } else {
                    self.backend.launch_app(&app, &trace_id)?
                };
                Ok(HostResponse::ActionCompleted {
                    trace_id,
                    audit_event_id: Uuid::nil(),
                    message,
                })
            }
            HostRequest::QuitApp {
                trace_id,
                session_id,
                app,
            } => {
                let request = HostRequest::QuitApp {
                    trace_id: trace_id.clone(),
                    session_id,
                    app: app.clone(),
                };
                self.authorize_or_approve_request(session_id, &request)?;
                let message = if self.is_dry_run(session_id, &trace_id)? {
                    "Dry-run policy prevented the action from executing.".to_string()
                } else {
                    self.backend.quit_app(&app, &trace_id)?
                };
                Ok(HostResponse::ActionCompleted {
                    trace_id,
                    audit_event_id: Uuid::nil(),
                    message,
                })
            }
            HostRequest::ListWindows { trace_id } => {
                self.authorize_standalone_capability(Capability::WindowList, &trace_id)?;
                Ok(HostResponse::WindowList {
                    windows: self.backend.list_windows(&trace_id)?,
                })
            }
            HostRequest::FocusWindow {
                trace_id,
                session_id,
                title,
            } => {
                let request = HostRequest::FocusWindow {
                    trace_id: trace_id.clone(),
                    session_id,
                    title: title.clone(),
                };
                self.authorize_or_approve_request(session_id, &request)?;
                let message = if self.is_dry_run(session_id, &trace_id)? {
                    "Dry-run policy prevented the action from executing.".to_string()
                } else {
                    self.backend.focus_window(&title, &trace_id)?
                };
                Ok(HostResponse::ActionCompleted {
                    trace_id,
                    audit_event_id: Uuid::nil(),
                    message,
                })
            }
            HostRequest::MoveWindow {
                trace_id,
                session_id,
                title,
                x,
                y,
            } => {
                let request = HostRequest::MoveWindow {
                    trace_id: trace_id.clone(),
                    session_id,
                    title: title.clone(),
                    x,
                    y,
                };
                self.authorize_or_approve_request(session_id, &request)?;
                let coordinate = Coordinate { x, y };
                let message = if self.is_dry_run(session_id, &trace_id)? {
                    "Dry-run policy prevented the action from executing.".to_string()
                } else {
                    self.backend
                        .move_window(&title, coordinate.clone(), &trace_id)?
                };
                Ok(HostResponse::ActionCompleted {
                    trace_id,
                    audit_event_id: Uuid::nil(),
                    message,
                })
            }
            HostRequest::ResizeWindow {
                trace_id,
                session_id,
                title,
                width,
                height,
            } => {
                let request = HostRequest::ResizeWindow {
                    trace_id: trace_id.clone(),
                    session_id,
                    title: title.clone(),
                    width,
                    height,
                };
                self.authorize_or_approve_request(session_id, &request)?;
                let message = if self.is_dry_run(session_id, &trace_id)? {
                    "Dry-run policy prevented the action from executing.".to_string()
                } else {
                    self.backend
                        .resize_window(&title, width, height, &trace_id)?
                };
                Ok(HostResponse::ActionCompleted {
                    trace_id,
                    audit_event_id: Uuid::nil(),
                    message,
                })
            }
            HostRequest::Capture { trace_id, screen } => {
                self.authorize_capture_request(screen.as_deref(), &trace_id)?;
                let artifact_id = Uuid::new_v4();
                let output_path = self.config.artifact_dir.join(format!("{artifact_id}.png"));
                self.backend
                    .capture(screen.as_deref(), &output_path, &trace_id)?;
                let bytes = std::fs::read(&output_path).map_err(|error| {
                    ToolError::internal(
                        format!(
                            "Failed to load captured artifact {}: {error}",
                            output_path.display()
                        ),
                        &trace_id,
                    )
                })?;
                let artifact = ObservationArtifact {
                    id: artifact_id,
                    path: output_path.display().to_string(),
                    sha256: desktop_core::hash_bytes(&bytes),
                    mime_type: "image/png".to_string(),
                    bytes: bytes.len(),
                    created_at: chrono::Utc::now(),
                };
                self.artifacts.insert(artifact.id, artifact.clone());
                Ok(HostResponse::ArtifactCaptured { artifact })
            }
            HostRequest::ReadOcr {
                trace_id,
                artifact_id,
            } => {
                self.authorize_standalone_capability(Capability::OcrRead, &trace_id)?;
                let artifact = self.require_artifact(artifact_id, &trace_id)?;
                let artifact_path = artifact.path.clone();
                let text = self
                    .backend
                    .read_ocr(Path::new(&artifact_path), &trace_id)?;
                Ok(HostResponse::OcrRead { artifact_id, text })
            }
            HostRequest::VisionDescribe {
                trace_id,
                artifact_id,
                ..
            } => {
                self.authorize_standalone_capability(Capability::VisionDescribe, &trace_id)?;
                let artifact = self.require_artifact(artifact_id, &trace_id)?;
                let summary = self.vision.describe(artifact, &trace_id)?;
                Ok(HostResponse::VisionDescription {
                    artifact_id,
                    summary,
                })
            }
            HostRequest::VisionLocate {
                trace_id,
                artifact_id,
                query,
            } => {
                self.authorize_standalone_capability(Capability::VisionLocate, &trace_id)?;
                let artifact = self.require_artifact(artifact_id, &trace_id)?;
                let target = self.vision.locate(artifact, &query, &trace_id)?;
                self.vision_targets.insert(target.id, target.clone());
                Ok(HostResponse::VisionLocated { target })
            }
            HostRequest::Click {
                trace_id,
                session_id,
                target_ref,
                coordinates,
            } => {
                self.evaluate_policy(
                    session_id,
                    &HostRequest::Click {
                        trace_id: trace_id.clone(),
                        session_id,
                        target_ref,
                        coordinates: coordinates.clone(),
                    },
                )?;
                let coordinate =
                    self.resolve_click_coordinate(target_ref, coordinates, &trace_id)?;
                let message = if self.is_dry_run(session_id, &trace_id)? {
                    "Dry-run policy prevented the action from executing.".to_string()
                } else {
                    self.backend.click(coordinate.clone(), &trace_id)?
                };
                Ok(HostResponse::ActionCompleted {
                    trace_id,
                    audit_event_id: Uuid::nil(),
                    message,
                })
            }
            HostRequest::TypeText {
                trace_id,
                session_id,
                text,
            } => {
                self.evaluate_policy(
                    session_id,
                    &HostRequest::TypeText {
                        trace_id: trace_id.clone(),
                        session_id,
                        text: text.clone(),
                    },
                )?;
                let message = if self.is_dry_run(session_id, &trace_id)? {
                    "Dry-run policy prevented the action from executing.".to_string()
                } else {
                    self.backend.type_text(&text, &trace_id)?
                };
                Ok(HostResponse::ActionCompleted {
                    trace_id,
                    audit_event_id: Uuid::nil(),
                    message,
                })
            }
            HostRequest::Hotkey {
                trace_id,
                session_id,
                keys,
            } => {
                self.evaluate_policy(
                    session_id,
                    &HostRequest::Hotkey {
                        trace_id: trace_id.clone(),
                        session_id,
                        keys: keys.clone(),
                    },
                )?;
                let message = if self.is_dry_run(session_id, &trace_id)? {
                    "Dry-run policy prevented the action from executing.".to_string()
                } else {
                    self.backend.hotkey(&keys, &trace_id)?
                };
                Ok(HostResponse::ActionCompleted {
                    trace_id,
                    audit_event_id: Uuid::nil(),
                    message,
                })
            }
        }
    }

    fn effective_capabilities(&self) -> Vec<BackendCapability> {
        self.backend
            .capabilities()
            .into_iter()
            .map(|capability| {
                if capability.supported
                    && !self.capability_allowed_by_host_policy(capability.capability)
                {
                    BackendCapability {
                        capability: capability.capability,
                        supported: false,
                        reason: Some(
                            "Disabled by the host security policy. Update policy.json to enable it."
                                .to_string(),
                        ),
                    }
                } else {
                    capability
                }
            })
            .collect()
    }

    fn append_audit_event(&self, event: &AuditEvent, trace_id: &str) -> Result<(), ToolError> {
        self.audit_store.append(event).map_err(|error| {
            ToolError::internal(format!("Failed to persist audit record: {error}"), trace_id)
        })
    }

    fn capability_allowed_by_host_policy(&self, capability: Capability) -> bool {
        if matches!(
            capability,
            Capability::DesktopCapabilities
                | Capability::DesktopPermissions
                | Capability::SessionOpen
                | Capability::SessionClose
        ) {
            return true;
        }

        if matches!(
            capability,
            Capability::AppLaunch
                | Capability::AppQuit
                | Capability::WindowFocus
                | Capability::WindowMove
                | Capability::WindowResize
                | Capability::InputClick
                | Capability::InputType
                | Capability::InputHotkey
        ) {
            return self
                .config
                .base_security_policy
                .allowed_session_capabilities
                .contains(&capability);
        }

        self.config
            .base_security_policy
            .allowed_standalone_capabilities
            .contains(&capability)
    }

    fn capability_supported_by_backend(&self, capability: Capability) -> bool {
        self.backend
            .capabilities()
            .into_iter()
            .find(|item| item.capability == capability)
            .map(|item| item.supported)
            .unwrap_or(false)
    }

    fn unsupported_error_for_capability(
        &self,
        capability: Capability,
        trace_id: &str,
    ) -> ToolError {
        let reason = self
            .backend
            .capabilities()
            .into_iter()
            .find(|item| item.capability == capability)
            .and_then(|item| item.reason)
            .unwrap_or_else(|| {
                format!(
                    "Capability {} is not supported by the current backend.",
                    capability.tool_name()
                )
            });
        ToolError::unsupported(reason, trace_id)
    }

    fn authorize_standalone_capability(
        &self,
        capability: Capability,
        trace_id: &str,
    ) -> Result<(), ToolError> {
        if !self.capability_supported_by_backend(capability) {
            return Err(self.unsupported_error_for_capability(capability, trace_id));
        }

        if self.capability_allowed_by_host_policy(capability) {
            return Ok(());
        }

        Err(ToolError::policy_denied(
            format!(
                "Capability {} is disabled by the host security policy.",
                capability.tool_name()
            ),
            trace_id,
        ))
    }

    fn authorize_capture_request(
        &self,
        screen: Option<&str>,
        trace_id: &str,
    ) -> Result<(), ToolError> {
        self.authorize_standalone_capability(Capability::ObserveCapture, trace_id)?;

        if self.config.security_policy.allowed_screens.is_empty() {
            return Err(ToolError::policy_denied(
                "The host security policy has not allowed any screens for screenshot capture.",
                trace_id,
            ));
        }

        let requested_screen = screen.unwrap_or("primary");
        if !self
            .config
            .security_policy
            .allowed_screens
            .iter()
            .any(|item| item == requested_screen)
        {
            return Err(ToolError::policy_denied(
                format!(
                    "The requested screen is outside the host security policy allowlist: {requested_screen}"
                ),
                trace_id,
            ));
        }

        if requested_screen != "primary" {
            return Err(ToolError::unsupported(
                "The current screenshot backend only supports the primary display.",
                trace_id,
            ));
        }

        Ok(())
    }

    fn constrain_session_policy(
        &mut self,
        mut requested: SessionPolicy,
        trace_id: &str,
    ) -> Result<SessionPolicy, ToolError> {
        let disallowed: Vec<_> = requested
            .capabilities
            .iter()
            .filter(|capability| {
                !self
                    .config
                    .base_security_policy
                    .allowed_session_capabilities
                    .contains(capability)
            })
            .map(|capability| capability.tool_name())
            .collect();

        if !disallowed.is_empty() {
            return Err(ToolError::policy_denied(
                format!(
                    "The host security policy does not allow these session capabilities: {}",
                    disallowed.join(", ")
                ),
                trace_id,
            ));
        }

        let unsupported: Vec<_> = requested
            .capabilities
            .iter()
            .filter(|capability| !self.capability_supported_by_backend(**capability))
            .map(|capability| {
                self.unsupported_error_for_capability(*capability, trace_id)
                    .message
            })
            .collect();

        if !unsupported.is_empty() {
            return Err(ToolError::unsupported(unsupported.join(" "), trace_id));
        }

        if requested.allow_raw_input && !self.config.base_security_policy.allow_raw_input {
            return Err(ToolError::policy_denied(
                "Raw coordinate input is disabled by the host security policy.",
                trace_id,
            ));
        }

        let max_actions = self
            .config
            .base_security_policy
            .max_actions_per_minute
            .max(1);
        requested.max_actions_per_minute = requested.max_actions_per_minute.clamp(1, max_actions);

        let app_capability_requested = requested
            .capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::AppLaunch | Capability::AppQuit));
        if app_capability_requested {
            let allowed_apps = self.config.security_policy.allowed_apps.clone();
            let app_group_supported = requested.capabilities.iter().any(|capability| {
                matches!(capability, Capability::AppLaunch | Capability::AppQuit)
                    && self.capability_supported_by_backend(*capability)
            });
            requested.allowed_apps = self.constrain_scope_with_approval(
                &requested.allowed_apps,
                &allowed_apps,
                ApprovalTargetKind::App,
                Capability::SessionOpen,
                trace_id,
                app_group_supported,
            )?;
        }

        let window_capability_requested = requested.capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::WindowFocus | Capability::WindowMove | Capability::WindowResize
            )
        });
        if window_capability_requested {
            let allowed_windows = self.config.security_policy.allowed_windows.clone();
            let window_group_supported = requested.capabilities.iter().any(|capability| {
                matches!(
                    capability,
                    Capability::WindowFocus | Capability::WindowMove | Capability::WindowResize
                ) && self.capability_supported_by_backend(*capability)
            });
            requested.allowed_windows = self.constrain_scope_with_approval(
                &requested.allowed_windows,
                &allowed_windows,
                ApprovalTargetKind::Window,
                Capability::SessionOpen,
                trace_id,
                window_group_supported,
            )?;
        }

        let input_capability_requested = requested.capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::InputClick | Capability::InputType | Capability::InputHotkey
            )
        });
        if input_capability_requested {
            let allowed_screens = self.config.security_policy.allowed_screens.clone();
            let input_group_supported = requested.capabilities.iter().any(|capability| {
                matches!(
                    capability,
                    Capability::InputClick | Capability::InputType | Capability::InputHotkey
                ) && self.capability_supported_by_backend(*capability)
            });
            requested.allowed_screens = self.constrain_scope_with_approval(
                &requested.allowed_screens,
                &allowed_screens,
                ApprovalTargetKind::Screen,
                Capability::SessionOpen,
                trace_id,
                input_group_supported,
            )?;
        }

        Ok(requested)
    }

    fn constrain_scope_with_approval(
        &mut self,
        requested: &[String],
        allowed: &[String],
        target_kind: ApprovalTargetKind,
        capability: Capability,
        trace_id: &str,
        approval_enabled: bool,
    ) -> Result<Vec<String>, ToolError> {
        if allowed.is_empty() && requested.is_empty() {
            return Err(ToolError::policy_denied(
                format!(
                    "The host security policy has not allowed any {} targets for this capability.",
                    target_kind.as_str()
                ),
                trace_id,
            ));
        }

        if requested.is_empty() {
            return Ok(allowed.to_vec());
        }

        let missing: Vec<_> = requested
            .iter()
            .filter(|target| !allowed.contains(*target))
            .cloned()
            .collect();

        if missing.is_empty() {
            return Ok(requested.to_vec());
        }

        if !approval_enabled || self.approval.is_none() {
            return Err(ToolError::policy_denied(
                format!(
                    "The requested {} target is outside the host security policy allowlist: {}",
                    target_kind.as_str(),
                    missing[0]
                ),
                trace_id,
            ));
        }

        for target in missing {
            self.request_runtime_approval(capability, target_kind, &target, None, trace_id)?;
        }

        Ok(requested.to_vec())
    }

    fn evaluate_policy(&self, session_id: Uuid, request: &HostRequest) -> Result<(), ToolError> {
        let session = self.sessions.get(&session_id).ok_or_else(|| {
            ToolError::not_found("The requested session does not exist.", request.trace_id())
        })?;
        self.policy_engine
            .evaluate(Some(session), &request.to_policy_request())?;
        Ok(())
    }

    fn authorize_or_approve_request(
        &mut self,
        session_id: Uuid,
        request: &HostRequest,
    ) -> Result<(), ToolError> {
        let capability = request.capability();
        if !self.capability_supported_by_backend(capability) {
            return Err(self.unsupported_error_for_capability(capability, request.trace_id()));
        }

        match self.evaluate_policy(session_id, request) {
            Ok(()) => Ok(()),
            Err(error) => match self.try_approve_request_scope(session_id, request, &error)? {
                ApprovalFlowResult::Applied => self.evaluate_policy(session_id, request),
                ApprovalFlowResult::Skipped => Err(error),
                ApprovalFlowResult::Denied(error) => Err(error),
            },
        }
    }

    fn try_approve_request_scope(
        &mut self,
        session_id: Uuid,
        request: &HostRequest,
        original_error: &ToolError,
    ) -> Result<ApprovalFlowResult, ToolError> {
        if original_error.code != desktop_core::ToolErrorCode::PolicyDenied {
            return Ok(ApprovalFlowResult::Skipped);
        }

        let capability = request.capability();
        if !self.capability_supported_by_backend(capability) {
            return Ok(ApprovalFlowResult::Denied(
                self.unsupported_error_for_capability(capability, request.trace_id()),
            ));
        }

        let Some((target_kind, target_value)) = self.approval_target_from_request(request) else {
            return Ok(ApprovalFlowResult::Skipped);
        };

        let session = match self.sessions.get(&session_id) {
            Some(session) => session,
            None => return Ok(ApprovalFlowResult::Skipped),
        };

        if session.is_expired() || !session.policy.capabilities.contains(&capability) {
            return Ok(ApprovalFlowResult::Skipped);
        }

        if self.session_scope_contains(session, target_kind, &target_value) {
            return Ok(ApprovalFlowResult::Skipped);
        }

        match self.request_runtime_approval(
            capability,
            target_kind,
            &target_value,
            Some(session_id),
            request.trace_id(),
        ) {
            Ok(()) => Ok(ApprovalFlowResult::Applied),
            Err(error) => Ok(ApprovalFlowResult::Denied(error)),
        }
    }

    fn approval_target_from_request(
        &self,
        request: &HostRequest,
    ) -> Option<(ApprovalTargetKind, String)> {
        match request {
            HostRequest::LaunchApp { app, .. } | HostRequest::QuitApp { app, .. } => {
                Some((ApprovalTargetKind::App, app.clone()))
            }
            HostRequest::FocusWindow { title, .. }
            | HostRequest::MoveWindow { title, .. }
            | HostRequest::ResizeWindow { title, .. } => {
                Some((ApprovalTargetKind::Window, title.clone()))
            }
            _ => None,
        }
    }

    fn session_scope_contains(
        &self,
        session: &Session,
        target_kind: ApprovalTargetKind,
        target_value: &str,
    ) -> bool {
        let targets = match target_kind {
            ApprovalTargetKind::App => &session.policy.allowed_apps,
            ApprovalTargetKind::Window => &session.policy.allowed_windows,
            ApprovalTargetKind::Screen => &session.policy.allowed_screens,
        };
        targets.iter().any(|item| item == target_value)
    }

    fn request_runtime_approval(
        &mut self,
        capability: Capability,
        target_kind: ApprovalTargetKind,
        target_value: &str,
        session_id: Option<Uuid>,
        trace_id: &str,
    ) -> Result<(), ToolError> {
        let Some(approval) = self.approval.as_ref() else {
            return Err(ToolError::policy_denied(
                format!(
                    "The requested {} target is outside the host security policy allowlist: {}",
                    target_kind.as_str(),
                    target_value
                ),
                trace_id,
            ));
        };

        let request = ApprovalRequest {
            capability,
            target_kind,
            target_value: target_value.to_string(),
            session_id,
            trace_id: trace_id.to_string(),
        };

        match approval.request(&request)? {
            ApprovalDecision::AllowPersist => self.persist_approved_target(
                capability,
                target_kind,
                target_value,
                session_id,
                trace_id,
            ),
            ApprovalDecision::Deny => {
                self.record_approval_audit(
                    ApprovalAudit {
                        capability,
                        session_id,
                        target_kind,
                        target_value,
                        decision: "approval_denied",
                        persisted: false,
                    },
                    trace_id,
                )?;
                Err(ToolError::policy_denied(
                    format!(
                        "The user denied approval for the {} target: {}",
                        target_kind.as_str(),
                        target_value
                    ),
                    trace_id,
                ))
            }
            ApprovalDecision::TimedOut => {
                self.record_approval_audit(
                    ApprovalAudit {
                        capability,
                        session_id,
                        target_kind,
                        target_value,
                        decision: "approval_timed_out",
                        persisted: false,
                    },
                    trace_id,
                )?;
                Err(ToolError::policy_denied(
                    format!(
                        "Approval timed out for the {} target: {}",
                        target_kind.as_str(),
                        target_value
                    ),
                    trace_id,
                ))
            }
        }
    }

    fn persist_approved_target(
        &mut self,
        capability: Capability,
        target_kind: ApprovalTargetKind,
        target_value: &str,
        session_id: Option<Uuid>,
        trace_id: &str,
    ) -> Result<(), ToolError> {
        let changed = self
            .config
            .overlay_policy
            .add_target(target_kind, target_value);
        if changed
            && let Err(error) = self
                .config
                .overlay_policy
                .persist(&self.config.overlay_policy_path)
        {
            self.record_approval_audit(
                ApprovalAudit {
                    capability,
                    session_id,
                    target_kind,
                    target_value,
                    decision: "approval_persist_failed",
                    persisted: false,
                },
                trace_id,
            )?;
            return Err(ToolError::internal(
                format!("Failed to persist overlay policy: {error}"),
                trace_id,
            ));
        }

        self.config.security_policy = self
            .config
            .base_security_policy
            .merged_with_overlay(&self.config.overlay_policy);

        if let Some(session_id) = session_id {
            self.extend_session_scope(session_id, target_kind, target_value, trace_id)?;
        }

        self.record_approval_audit(
            ApprovalAudit {
                capability,
                session_id,
                target_kind,
                target_value,
                decision: "approval_allowed_persisted",
                persisted: true,
            },
            trace_id,
        )?;
        Ok(())
    }

    fn extend_session_scope(
        &mut self,
        session_id: Uuid,
        target_kind: ApprovalTargetKind,
        target_value: &str,
        trace_id: &str,
    ) -> Result<(), ToolError> {
        let session = self.sessions.get_mut(&session_id).ok_or_else(|| {
            ToolError::not_found("The requested session does not exist.", trace_id)
        })?;

        let targets = match target_kind {
            ApprovalTargetKind::App => &mut session.policy.allowed_apps,
            ApprovalTargetKind::Window => &mut session.policy.allowed_windows,
            ApprovalTargetKind::Screen => &mut session.policy.allowed_screens,
        };

        if !targets.iter().any(|item| item == target_value) {
            targets.push(target_value.to_string());
            targets.sort();
        }

        Ok(())
    }

    fn record_approval_audit(
        &self,
        approval: ApprovalAudit<'_>,
        trace_id: &str,
    ) -> Result<(), ToolError> {
        let payload = desktop_core::AuditPayload::from_preview_and_sensitive_text(
            format!(
                "target_kind={} persisted={}",
                approval.target_kind.as_str(),
                approval.persisted
            ),
            format!("target_value={}", approval.target_value),
        );
        let event = AuditEvent::new(
            trace_id.to_string(),
            approval.capability,
            approval.decision,
            approval.session_id,
            payload,
        );
        self.append_audit_event(&event, trace_id)
    }

    fn is_dry_run(&self, session_id: Uuid, trace_id: &str) -> Result<bool, ToolError> {
        let session = self.sessions.get(&session_id).ok_or_else(|| {
            ToolError::not_found("The requested session does not exist.", trace_id)
        })?;
        Ok(session.policy.dry_run)
    }

    fn require_artifact(
        &self,
        artifact_id: Uuid,
        trace_id: &str,
    ) -> Result<&ObservationArtifact, ToolError> {
        self.artifacts
            .get(&artifact_id)
            .ok_or_else(|| ToolError::not_found("The requested artifact does not exist.", trace_id))
    }

    fn resolve_click_coordinate(
        &self,
        target_ref: Option<Uuid>,
        coordinates: Option<Coordinate>,
        trace_id: &str,
    ) -> Result<Coordinate, ToolError> {
        if let Some(target_ref) = target_ref {
            let target = self.vision_targets.get(&target_ref).ok_or_else(|| {
                ToolError::not_found("The requested target reference does not exist.", trace_id)
            })?;
            if chrono::Utc::now() >= target.expires_at {
                return Err(ToolError::not_found(
                    "The requested target reference has expired.",
                    trace_id,
                ));
            }
            return Ok(Coordinate {
                x: target.bbox.x + (target.bbox.width / 2) as i32,
                y: target.bbox.y + (target.bbox.height / 2) as i32,
            });
        }

        coordinates.ok_or_else(|| {
            ToolError::validation(
                "input.click requires either a target_ref or explicit coordinates.",
                trace_id,
            )
        })
    }
}

fn default_approval_broker(platform_name: &str) -> Option<Box<dyn ApprovalBroker>> {
    if platform_name == "macos" {
        Some(Box::new(MacOsApprovalBroker))
    } else {
        None
    }
}

fn apple_script_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\""))
}

fn run_macos_apple_script(
    script: &str,
    action_label: &str,
    trace_id: &str,
) -> Result<String, ToolError> {
    let mut command = Command::new("/usr/bin/osascript");
    command.arg("-e").arg(script);
    let (status, stdout, stderr) = wait_for_command_output(
        &mut command,
        StdDuration::from_secs(COMMAND_TIMEOUT_SECS),
        action_label,
        trace_id,
    )?;

    if status.success() {
        return Ok(stdout);
    }

    let diagnostics = stderr.trim();
    if diagnostics.contains("WINDOW_NOT_FOUND") {
        return Err(ToolError::not_found(
            "The requested window could not be found.",
            trace_id,
        ));
    }

    if diagnostics.contains("not allowed assistive access")
        || diagnostics.contains("Not authorized to send Apple events")
        || diagnostics.contains("(-1743)")
    {
        return Err(ToolError::unsupported(
            ACCESSIBILITY_PERMISSION_REASON,
            trace_id,
        ));
    }

    Err(ToolError::internal(
        if diagnostics.is_empty() {
            format!("{action_label} failed with status {}.", status)
        } else {
            format!("{action_label} failed: {diagnostics}")
        },
        trace_id,
    ))
}

fn parse_macos_window_list(output: &str) -> Vec<WindowDescriptor> {
    output
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 6 {
                return None;
            }

            let position = match (fields[2].parse::<i32>(), fields[3].parse::<i32>()) {
                (Ok(x), Ok(y)) => Some(Coordinate { x, y }),
                _ => None,
            };
            let size = match (fields[4].parse::<u32>(), fields[5].parse::<u32>()) {
                (Ok(width), Ok(height)) => Some(desktop_core::Size { width, height }),
                _ => None,
            };

            Some(WindowDescriptor {
                id: format!("{}:{}:{index}", fields[0], fields[1]),
                title: fields[1].to_string(),
                app_name: Some(fields[0].to_string()),
                position,
                size,
            })
        })
        .collect()
}

fn new_enigo(trace_id: &str) -> Result<Enigo, ToolError> {
    Enigo::new(&Settings::default()).map_err(|error| {
        ToolError::internal(
            format!("Desktop input controller could not be initialized: {error}"),
            trace_id,
        )
    })
}

fn parse_hotkey_key(value: &str, trace_id: &str) -> Result<Key, ToolError> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(ToolError::validation(
            "Hotkey entries must not be empty.",
            trace_id,
        ));
    }

    let lower = normalized.to_ascii_lowercase();
    let key = match lower.as_str() {
        "alt" | "option" => Key::Alt,
        "backspace" => Key::Backspace,
        "capslock" => Key::CapsLock,
        "command" | "cmd" | "meta" | "super" => Key::Meta,
        "control" | "ctrl" => Key::Control,
        "delete" => Key::Delete,
        "down" | "arrowdown" => Key::DownArrow,
        "end" => Key::End,
        "enter" | "return" => Key::Return,
        "escape" | "esc" => Key::Escape,
        "home" => Key::Home,
        "left" | "arrowleft" => Key::LeftArrow,
        "pagedown" => Key::PageDown,
        "pageup" => Key::PageUp,
        "right" | "arrowright" => Key::RightArrow,
        "shift" => Key::Shift,
        "space" => Key::Space,
        "tab" => Key::Tab,
        "up" | "arrowup" => Key::UpArrow,
        "f1" => Key::F1,
        "f2" => Key::F2,
        "f3" => Key::F3,
        "f4" => Key::F4,
        "f5" => Key::F5,
        "f6" => Key::F6,
        "f7" => Key::F7,
        "f8" => Key::F8,
        "f9" => Key::F9,
        "f10" => Key::F10,
        "f11" => Key::F11,
        "f12" => Key::F12,
        _ => {
            let mut chars = normalized.chars();
            match (chars.next(), chars.next()) {
                (Some(ch), None) => Key::Unicode(ch.to_ascii_lowercase()),
                _ => {
                    return Err(ToolError::validation(
                        format!("Unsupported hotkey token: {normalized}"),
                        trace_id,
                    ));
                }
            }
        }
    };

    Ok(key)
}

fn system_backend_capabilities(
    platform: &str,
    accessibility: PermissionState,
    screen_recording: PermissionState,
    tesseract_installed: bool,
    vision_configured: bool,
) -> Vec<BackendCapability> {
    let supported = |capability| BackendCapability {
        capability,
        supported: true,
        reason: None,
    };
    let unsupported = |capability, reason: &str| BackendCapability {
        capability,
        supported: false,
        reason: Some(reason.to_string()),
    };

    let mac_permission_gate = |capability, state: PermissionState, reason: &str| match state {
        PermissionState::Granted => supported(capability),
        PermissionState::Denied => unsupported(capability, reason),
        PermissionState::NotChecked => unsupported(capability, reason),
        PermissionState::NotSupported => unsupported(
            capability,
            "This capability is not supported by the current platform permissions model.",
        ),
    };

    match platform {
        "macos" => vec![
            supported(Capability::AppList),
            supported(Capability::AppLaunch),
            unsupported(
                Capability::AppQuit,
                "Graceful app quit is not implemented yet.",
            ),
            mac_permission_gate(
                Capability::WindowList,
                accessibility,
                ACCESSIBILITY_PERMISSION_REASON,
            ),
            mac_permission_gate(
                Capability::WindowFocus,
                accessibility,
                ACCESSIBILITY_PERMISSION_REASON,
            ),
            mac_permission_gate(
                Capability::WindowMove,
                accessibility,
                ACCESSIBILITY_PERMISSION_REASON,
            ),
            mac_permission_gate(
                Capability::WindowResize,
                accessibility,
                ACCESSIBILITY_PERMISSION_REASON,
            ),
            mac_permission_gate(
                Capability::ObserveCapture,
                screen_recording,
                SCREEN_RECORDING_PERMISSION_REASON,
            ),
            if tesseract_installed {
                mac_permission_gate(
                    Capability::OcrRead,
                    screen_recording,
                    SCREEN_RECORDING_PERMISSION_REASON,
                )
            } else {
                unsupported(
                    Capability::OcrRead,
                    "OCR requires the `tesseract` binary to be installed and available on PATH.",
                )
            },
            if vision_configured {
                mac_permission_gate(
                    Capability::VisionDescribe,
                    screen_recording,
                    SCREEN_RECORDING_PERMISSION_REASON,
                )
            } else {
                unsupported(
                    Capability::VisionDescribe,
                    "No vision provider has been configured.",
                )
            },
            if vision_configured {
                mac_permission_gate(
                    Capability::VisionLocate,
                    screen_recording,
                    SCREEN_RECORDING_PERMISSION_REASON,
                )
            } else {
                unsupported(
                    Capability::VisionLocate,
                    "No vision provider has been configured.",
                )
            },
            mac_permission_gate(
                Capability::InputClick,
                accessibility,
                ACCESSIBILITY_PERMISSION_REASON,
            ),
            mac_permission_gate(
                Capability::InputType,
                accessibility,
                ACCESSIBILITY_PERMISSION_REASON,
            ),
            mac_permission_gate(
                Capability::InputHotkey,
                accessibility,
                ACCESSIBILITY_PERMISSION_REASON,
            ),
        ],
        "windows" => vec![
            supported(Capability::AppList),
            supported(Capability::AppLaunch),
            unsupported(
                Capability::AppQuit,
                "Graceful app quit is not implemented yet.",
            ),
            unsupported(
                Capability::WindowList,
                "Window management backends are not implemented yet on Windows.",
            ),
            unsupported(
                Capability::WindowFocus,
                "Window management backends are not implemented yet on Windows.",
            ),
            unsupported(
                Capability::WindowMove,
                "Window management backends are not implemented yet on Windows.",
            ),
            unsupported(
                Capability::WindowResize,
                "Window management backends are not implemented yet on Windows.",
            ),
            supported(Capability::ObserveCapture),
            if tesseract_installed {
                supported(Capability::OcrRead)
            } else {
                unsupported(
                    Capability::OcrRead,
                    "OCR requires the `tesseract` binary to be installed and available on PATH.",
                )
            },
            unsupported(
                Capability::VisionDescribe,
                "No vision provider has been configured.",
            ),
            unsupported(
                Capability::VisionLocate,
                "No vision provider has been configured.",
            ),
            unsupported(
                Capability::InputClick,
                "Input control is not implemented yet on Windows.",
            ),
            unsupported(
                Capability::InputType,
                "Input control is not implemented yet on Windows.",
            ),
            unsupported(
                Capability::InputHotkey,
                "Input control is not implemented yet on Windows.",
            ),
        ],
        _ => vec![
            supported(Capability::AppList),
            supported(Capability::AppLaunch),
            unsupported(
                Capability::AppQuit,
                "Graceful app quit is not implemented yet.",
            ),
            unsupported(
                Capability::WindowList,
                "Window management backends are not implemented yet on this platform.",
            ),
            unsupported(
                Capability::WindowFocus,
                "Window management backends are not implemented yet on this platform.",
            ),
            unsupported(
                Capability::WindowMove,
                "Window management backends are not implemented yet on this platform.",
            ),
            unsupported(
                Capability::WindowResize,
                "Window management backends are not implemented yet on this platform.",
            ),
            supported(Capability::ObserveCapture),
            if tesseract_installed {
                supported(Capability::OcrRead)
            } else {
                unsupported(
                    Capability::OcrRead,
                    "OCR requires the `tesseract` binary to be installed and available on PATH.",
                )
            },
            unsupported(
                Capability::VisionDescribe,
                "No vision provider has been configured.",
            ),
            unsupported(
                Capability::VisionLocate,
                "No vision provider has been configured.",
            ),
            unsupported(
                Capability::InputClick,
                "Input control is not implemented yet on this platform.",
            ),
            unsupported(
                Capability::InputType,
                "Input control is not implemented yet on this platform.",
            ),
            unsupported(
                Capability::InputHotkey,
                "Input control is not implemented yet on this platform.",
            ),
        ],
    }
}

fn system_permission_statuses(
    platform: &str,
    accessibility: PermissionState,
    screen_recording: PermissionState,
) -> Vec<PermissionStatus> {
    match platform {
        "macos" => vec![
            PermissionStatus {
                name: "accessibility".to_string(),
                state: accessibility,
                required_for: vec![
                    Capability::WindowList,
                    Capability::WindowFocus,
                    Capability::WindowMove,
                    Capability::WindowResize,
                    Capability::InputClick,
                    Capability::InputType,
                    Capability::InputHotkey,
                ],
                details: "Grant Accessibility permission in System Settings before enabling control actions.".to_string(),
            },
            PermissionStatus {
                name: "screen_recording".to_string(),
                state: screen_recording,
                required_for: vec![
                    Capability::ObserveCapture,
                    Capability::OcrRead,
                    Capability::VisionDescribe,
                    Capability::VisionLocate,
                ],
                details: "Grant Screen Recording permission before using screenshot-driven tooling.".to_string(),
            },
        ],
        "windows" => vec![PermissionStatus {
            name: "ui_automation".to_string(),
            state: PermissionState::NotChecked,
            required_for: vec![
                Capability::WindowFocus,
                Capability::WindowMove,
                Capability::WindowResize,
                Capability::InputClick,
                Capability::InputType,
                Capability::InputHotkey,
            ],
            details: "Additional Windows automation capability probing is not implemented yet.".to_string(),
        }],
        _ => vec![PermissionStatus {
            name: "desktop_access".to_string(),
            state: PermissionState::NotChecked,
            required_for: vec![
                Capability::ObserveCapture,
                Capability::InputClick,
                Capability::InputType,
                Capability::InputHotkey,
            ],
            details: "Linux permissions depend on the active display server; Wayland remains observation-only for now.".to_string(),
        }],
    }
}

fn command_exists(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn vision_provider_configured() -> bool {
    load_vision_command_config()
        .ok()
        .flatten()
        .is_some_and(|config| executable_is_available(&config.command))
}

fn probe_accessibility_permission() -> PermissionState {
    #[cfg(target_os = "macos")]
    {
        probe_macos_permission(
            r#"import ApplicationServices
print(AXIsProcessTrusted() ? "granted" : "denied")"#,
        )
    }

    #[cfg(not(target_os = "macos"))]
    {
        PermissionState::NotChecked
    }
}

fn probe_screen_recording_permission() -> PermissionState {
    #[cfg(target_os = "macos")]
    {
        probe_macos_permission(
            r#"import CoreGraphics
print(CGPreflightScreenCaptureAccess() ? "granted" : "denied")"#,
        )
    }

    #[cfg(not(target_os = "macos"))]
    {
        PermissionState::NotChecked
    }
}

#[cfg(target_os = "macos")]
fn probe_macos_permission(script: &str) -> PermissionState {
    let mut command = Command::new("swift");
    command.arg("-e").arg(script);
    match wait_for_command_output(
        &mut command,
        StdDuration::from_secs(COMMAND_TIMEOUT_SECS),
        "macOS permission probe",
        "permission-probe",
    ) {
        Ok((status, stdout, _)) if status.success() => match stdout.trim() {
            "granted" => PermissionState::Granted,
            "denied" => PermissionState::Denied,
            _ => PermissionState::NotChecked,
        },
        _ => PermissionState::NotChecked,
    }
}

#[cfg(not(target_os = "macos"))]
fn probe_macos_permission(_script: &str) -> PermissionState {
    PermissionState::NotChecked
}

fn executable_is_available(command: &str) -> bool {
    let path = Path::new(command);
    if path.components().count() > 1 {
        return path.is_file();
    }

    let locator = if cfg!(windows) { "where" } else { "which" };
    Command::new(locator)
        .arg(command)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn load_vision_command_config() -> Result<Option<VisionCommandConfig>> {
    let Some(command) = std::env::var_os(VISION_COMMAND_ENV_VAR) else {
        return Ok(None);
    };
    let command = command.to_string_lossy().trim().to_string();
    if command.is_empty() {
        return Ok(None);
    }

    let args = match std::env::var_os(VISION_ARGS_ENV_VAR) {
        Some(raw) => parse_vision_args(&raw.to_string_lossy())?,
        None => Vec::new(),
    };

    Ok(Some(VisionCommandConfig { command, args }))
}

fn parse_vision_args(raw: &str) -> Result<Vec<String>> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    serde_json::from_str(raw).context("failed to parse LAZY_DESKTOP_VISION_ARGS as JSON array")
}

fn build_vision_adapter(config: &HostServiceConfig) -> Box<dyn VisionAdapter> {
    match config.vision_command.clone() {
        Some(command) if executable_is_available(&command.command) => {
            Box::new(CliVisionAdapter::new(command.command, command.args))
        }
        _ => Box::<DisabledVisionAdapter>::default(),
    }
}

fn wait_for_command_success(
    command: &mut Command,
    timeout: StdDuration,
    action_label: &str,
    trace_id: &str,
) -> Result<(), ToolError> {
    let mut child = command.spawn().map_err(|error| {
        ToolError::internal(
            format!("{action_label} could not be started: {error}"),
            trace_id,
        )
    })?;

    match child.wait_timeout(timeout).map_err(|error| {
        ToolError::internal(
            format!("{action_label} could not be monitored: {error}"),
            trace_id,
        )
    })? {
        Some(status) if status.success() => Ok(()),
        Some(status) => Err(ToolError::internal(
            format!(
                "{action_label} failed with status {}.",
                status
                    .code()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "terminated".to_string())
            ),
            trace_id,
        )),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            Err(ToolError::internal(
                format!(
                    "{action_label} timed out after {} seconds.",
                    timeout.as_secs()
                ),
                trace_id,
            ))
        }
    }
}

fn wait_for_command_output(
    command: &mut Command,
    timeout: StdDuration,
    action_label: &str,
    trace_id: &str,
) -> Result<(std::process::ExitStatus, String, String), ToolError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        ToolError::internal(
            format!("{action_label} could not be started: {error}"),
            trace_id,
        )
    })?;

    let status = match child.wait_timeout(timeout).map_err(|error| {
        ToolError::internal(
            format!("{action_label} could not be monitored: {error}"),
            trace_id,
        )
    })? {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ToolError::internal(
                format!(
                    "{action_label} timed out after {} seconds.",
                    timeout.as_secs()
                ),
                trace_id,
            ));
        }
    };

    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_string(&mut stdout).map_err(|error| {
            ToolError::internal(
                format!("{action_label} output could not be read: {error}"),
                trace_id,
            )
        })?;
    }

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr).map_err(|error| {
            ToolError::internal(
                format!("{action_label} diagnostics could not be read: {error}"),
                trace_id,
            )
        })?;
    }

    Ok((status, stdout, stderr))
}

fn capture_command_stdout(
    command: &mut Command,
    timeout: StdDuration,
    action_label: &str,
    trace_id: &str,
) -> Result<String, ToolError> {
    let (status, stdout, stderr) =
        wait_for_command_output(command, timeout, action_label, trace_id)?;

    if !status.success() {
        let detail = if stderr.trim().is_empty() {
            format!(
                "{action_label} failed with status {}.",
                status
                    .code()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "terminated".to_string())
            )
        } else {
            format!("{action_label} failed: {}", stderr.trim())
        };
        Err(ToolError::internal(detail, trace_id))
    } else {
        Ok(stdout)
    }
}

fn capture_command_stdout_with_stdin(
    command: &str,
    args: &[String],
    input: &[u8],
    timeout: StdDuration,
    action_label: &str,
    trace_id: &str,
) -> Result<String, ToolError> {
    let mut process = Command::new(command);
    process
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = process.spawn().map_err(|error| {
        ToolError::internal(
            format!("{action_label} could not be started: {error}"),
            trace_id,
        )
    })?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input).map_err(|error| {
            ToolError::internal(
                format!("{action_label} input could not be written: {error}"),
                trace_id,
            )
        })?;
    }

    let status = match child.wait_timeout(timeout).map_err(|error| {
        ToolError::internal(
            format!("{action_label} could not be monitored: {error}"),
            trace_id,
        )
    })? {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ToolError::internal(
                format!(
                    "{action_label} timed out after {} seconds.",
                    timeout.as_secs()
                ),
                trace_id,
            ));
        }
    };

    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_string(&mut stdout).map_err(|error| {
            ToolError::internal(
                format!("{action_label} output could not be read: {error}"),
                trace_id,
            )
        })?;
    }

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr).map_err(|error| {
            ToolError::internal(
                format!("{action_label} diagnostics could not be read: {error}"),
                trace_id,
            )
        })?;
    }

    if !status.success() {
        let detail = if stderr.trim().is_empty() {
            format!(
                "{action_label} failed with status {}.",
                status
                    .code()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "terminated".to_string())
            )
        } else {
            format!("{action_label} failed: {}", stderr.trim())
        };
        Err(ToolError::internal(detail, trace_id))
    } else {
        Ok(stdout)
    }
}

fn invoke_vision_adapter(
    command: &str,
    args: &[String],
    payload: &Value,
    trace_id: &str,
) -> Result<Value, ToolError> {
    let body = serde_json::to_vec(payload).map_err(|error| {
        ToolError::internal(
            format!("Vision request could not be serialized: {error}"),
            trace_id,
        )
    })?;
    let stdout = capture_command_stdout_with_stdin(
        command,
        args,
        &body,
        StdDuration::from_secs(COMMAND_TIMEOUT_SECS),
        "Vision command",
        trace_id,
    )?;
    serde_json::from_str(stdout.trim()).map_err(|error| {
        ToolError::internal(
            format!("Vision command returned invalid JSON: {error}"),
            trace_id,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{system_backend_capabilities, system_permission_statuses};
    use desktop_core::{Capability, PermissionState};

    #[test]
    fn macos_capabilities_reflect_permissions_and_optional_tools() {
        let capabilities = system_backend_capabilities(
            "macos",
            PermissionState::Granted,
            PermissionState::Granted,
            true,
            false,
        );

        let is_supported = |capability| {
            capabilities
                .iter()
                .find(|item| item.capability == capability)
                .map(|item| item.supported)
                .unwrap_or(false)
        };

        assert!(is_supported(Capability::WindowList));
        assert!(is_supported(Capability::WindowFocus));
        assert!(is_supported(Capability::WindowMove));
        assert!(is_supported(Capability::WindowResize));
        assert!(is_supported(Capability::InputClick));
        assert!(is_supported(Capability::InputType));
        assert!(is_supported(Capability::InputHotkey));
        assert!(is_supported(Capability::ObserveCapture));
        assert!(is_supported(Capability::OcrRead));
        assert!(!is_supported(Capability::VisionDescribe));
        assert!(!is_supported(Capability::VisionLocate));
    }

    #[test]
    fn macos_permissions_are_reported_with_probe_results() {
        let permissions =
            system_permission_statuses("macos", PermissionState::Denied, PermissionState::Granted);

        assert_eq!(permissions.len(), 2);
        assert_eq!(permissions[0].name, "accessibility");
        assert_eq!(permissions[0].state, PermissionState::Denied);
        assert_eq!(permissions[1].name, "screen_recording");
        assert_eq!(permissions[1].state, PermissionState::Granted);
    }
}
