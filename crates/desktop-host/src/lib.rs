use anyhow::{Context, Result};
use chrono::Duration;
use desktop_core::{
    AppDescriptor, AuditEvent, BackendCapability, Capability, Coordinate, HostRequest,
    HostResponse, ObservationArtifact, PermissionState, PermissionStatus, PolicyEngine, Session,
    SessionPolicy, ToolError, VisionTarget, WindowDescriptor,
};
use directories::ProjectDirs;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration as StdDuration;
use sysinfo::{ProcessesToUpdate, System};
use uuid::Uuid;
use wait_timeout::ChildExt;

const COMMAND_TIMEOUT_SECS: u64 = 10;
const DEFAULT_SESSION_TTL_MINUTES: i64 = 15;
const DEFAULT_MAX_ACTIONS_PER_MINUTE: usize = 30;
const POLICY_PATH_ENV_VAR: &str = "LAZY_DESKTOP_POLICY_PATH";

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
}

#[derive(Debug, Clone)]
pub struct HostServiceConfig {
    pub audit_db_path: PathBuf,
    pub artifact_dir: PathBuf,
    pub session_ttl: Duration,
    pub security_policy: HostSecurityPolicy,
    pub security_policy_path: PathBuf,
}

impl HostServiceConfig {
    pub fn load() -> Result<Self> {
        let project_dirs = ProjectDirs::from("dev", "lazy", "desktop-mcp")
            .context("unable to resolve application data directory")?;
        let data_dir = project_dirs.data_local_dir();
        let security_policy_path = std::env::var_os(POLICY_PATH_ENV_VAR)
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("policy.json"));

        Ok(Self {
            audit_db_path: data_dir.join("audit.db"),
            artifact_dir: data_dir.join("artifacts"),
            session_ttl: Duration::minutes(DEFAULT_SESSION_TTL_MINUTES),
            security_policy: HostSecurityPolicy::load(&security_policy_path)?,
            security_policy_path,
        })
    }

    pub fn for_test(root: &Path) -> Self {
        Self {
            audit_db_path: root.join("audit.db"),
            artifact_dir: root.join("artifacts"),
            session_ttl: Duration::minutes(DEFAULT_SESSION_TTL_MINUTES),
            security_policy: HostSecurityPolicy::for_test(),
            security_policy_path: root.join("policy.json"),
        }
    }

    pub fn with_security_policy(mut self, security_policy: HostSecurityPolicy) -> Self {
        self.security_policy = security_policy;
        self
    }
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
        let unsupported = |capability, reason: &str| BackendCapability {
            capability,
            supported: false,
            reason: Some(reason.to_string()),
        };

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
            unsupported(
                Capability::AppQuit,
                "Graceful app quit is not implemented yet.",
            ),
            unsupported(
                Capability::WindowList,
                "Window management backends are not implemented yet.",
            ),
            unsupported(
                Capability::WindowFocus,
                "Window management backends are not implemented yet.",
            ),
            unsupported(
                Capability::WindowMove,
                "Window management backends are not implemented yet.",
            ),
            unsupported(
                Capability::WindowResize,
                "Window management backends are not implemented yet.",
            ),
            BackendCapability {
                capability: Capability::ObserveCapture,
                supported: true,
                reason: None,
            },
            unsupported(Capability::OcrRead, "OCR requires the tesseract binary."),
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
                "Input control is not implemented yet.",
            ),
            unsupported(
                Capability::InputType,
                "Input control is not implemented yet.",
            ),
            unsupported(
                Capability::InputHotkey,
                "Input control is not implemented yet.",
            ),
        ]
    }

    fn permission_statuses(&self) -> Vec<PermissionStatus> {
        match std::env::consts::OS {
            "macos" => vec![
                PermissionStatus {
                    name: "accessibility".to_string(),
                    state: PermissionState::NotChecked,
                    required_for: vec![
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
                    state: PermissionState::NotChecked,
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
        ]
    }

    fn permission_statuses(&self) -> Vec<PermissionStatus> {
        vec![PermissionStatus {
            name: "test_mode".to_string(),
            state: PermissionState::Granted,
            required_for: vec![Capability::AppLaunch],
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

        Ok(Self {
            backend,
            policy_engine: PolicyEngine::default(),
            audit_store,
            sessions: HashMap::new(),
            artifacts: HashMap::new(),
            vision_targets: HashMap::new(),
            config,
            vision: Box::<DisabledVisionAdapter>::default(),
        })
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
        self.audit_store.append(&audit_event).map_err(|error| {
            ToolError::internal(
                format!("Failed to persist audit record: {error}"),
                &trace_id,
            )
        })?;

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
                self.evaluate_policy(
                    session_id,
                    &HostRequest::LaunchApp {
                        trace_id: trace_id.clone(),
                        session_id,
                        app: app.clone(),
                    },
                )?;
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
                self.evaluate_policy(
                    session_id,
                    &HostRequest::QuitApp {
                        trace_id: trace_id.clone(),
                        session_id,
                        app: app.clone(),
                    },
                )?;
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
                self.evaluate_policy(
                    session_id,
                    &HostRequest::FocusWindow {
                        trace_id: trace_id.clone(),
                        session_id,
                        title: title.clone(),
                    },
                )?;
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
                self.evaluate_policy(
                    session_id,
                    &HostRequest::MoveWindow {
                        trace_id: trace_id.clone(),
                        session_id,
                        title: title.clone(),
                        x,
                        y,
                    },
                )?;
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
                self.evaluate_policy(
                    session_id,
                    &HostRequest::ResizeWindow {
                        trace_id: trace_id.clone(),
                        session_id,
                        title: title.clone(),
                        width,
                        height,
                    },
                )?;
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
                .security_policy
                .allowed_session_capabilities
                .contains(&capability);
        }

        self.config
            .security_policy
            .allowed_standalone_capabilities
            .contains(&capability)
    }

    fn authorize_standalone_capability(
        &self,
        capability: Capability,
        trace_id: &str,
    ) -> Result<(), ToolError> {
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
        &self,
        mut requested: SessionPolicy,
        trace_id: &str,
    ) -> Result<SessionPolicy, ToolError> {
        let disallowed: Vec<_> = requested
            .capabilities
            .iter()
            .filter(|capability| {
                !self
                    .config
                    .security_policy
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

        if requested.allow_raw_input && !self.config.security_policy.allow_raw_input {
            return Err(ToolError::policy_denied(
                "Raw coordinate input is disabled by the host security policy.",
                trace_id,
            ));
        }

        let max_actions = self.config.security_policy.max_actions_per_minute.max(1);
        requested.max_actions_per_minute = requested.max_actions_per_minute.clamp(1, max_actions);

        if requested
            .capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::AppLaunch | Capability::AppQuit))
        {
            requested.allowed_apps = self.constrain_scope(
                &requested.allowed_apps,
                &self.config.security_policy.allowed_apps,
                "app",
                trace_id,
            )?;
        }

        if requested.capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::WindowFocus | Capability::WindowMove | Capability::WindowResize
            )
        }) {
            requested.allowed_windows = self.constrain_scope(
                &requested.allowed_windows,
                &self.config.security_policy.allowed_windows,
                "window",
                trace_id,
            )?;
        }

        if requested.capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::InputClick | Capability::InputType | Capability::InputHotkey
            )
        }) {
            requested.allowed_screens = self.constrain_scope(
                &requested.allowed_screens,
                &self.config.security_policy.allowed_screens,
                "screen",
                trace_id,
            )?;
        }

        Ok(requested)
    }

    fn constrain_scope(
        &self,
        requested: &[String],
        allowed: &[String],
        scope_name: &str,
        trace_id: &str,
    ) -> Result<Vec<String>, ToolError> {
        if allowed.is_empty() {
            return Err(ToolError::policy_denied(
                format!(
                    "The host security policy has not allowed any {scope_name} targets for this capability."
                ),
                trace_id,
            ));
        }

        if requested.is_empty() {
            return Ok(allowed.to_vec());
        }

        if let Some(target) = requested.iter().find(|target| !allowed.contains(target)) {
            return Err(ToolError::policy_denied(
                format!(
                    "The requested {scope_name} target is outside the host security policy allowlist: {target}"
                ),
                trace_id,
            ));
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

fn capture_command_stdout(
    command: &mut Command,
    timeout: StdDuration,
    action_label: &str,
    trace_id: &str,
) -> Result<String, ToolError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
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
        Some(status) => {
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
                return Err(ToolError::internal(detail, trace_id));
            }

            Ok(stdout)
        }
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
