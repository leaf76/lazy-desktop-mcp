use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

const DEFAULT_TRACE_ID: &str = "trace-local";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    DesktopCapabilities,
    DesktopPermissions,
    SessionOpen,
    SessionClose,
    AppList,
    AppLaunch,
    AppQuit,
    WindowList,
    WindowFocus,
    WindowMove,
    WindowResize,
    ObserveCapture,
    OcrRead,
    VisionDescribe,
    VisionLocate,
    InputClick,
    InputType,
    InputHotkey,
}

impl Capability {
    pub fn tool_name(self) -> &'static str {
        match self {
            Self::DesktopCapabilities => "desktop.capabilities",
            Self::DesktopPermissions => "desktop.permissions",
            Self::SessionOpen => "session.open",
            Self::SessionClose => "session.close",
            Self::AppList => "app.list",
            Self::AppLaunch => "app.launch",
            Self::AppQuit => "app.quit",
            Self::WindowList => "window.list",
            Self::WindowFocus => "window.focus",
            Self::WindowMove => "window.move",
            Self::WindowResize => "window.resize",
            Self::ObserveCapture => "observe.capture",
            Self::OcrRead => "ocr.read",
            Self::VisionDescribe => "vision.describe",
            Self::VisionLocate => "vision.locate",
            Self::InputClick => "input.click",
            Self::InputType => "input.type",
            Self::InputHotkey => "input.hotkey",
        }
    }

    pub fn requires_session(self) -> bool {
        matches!(
            self,
            Self::AppLaunch
                | Self::AppQuit
                | Self::WindowFocus
                | Self::WindowMove
                | Self::WindowResize
                | Self::InputClick
                | Self::InputType
                | Self::InputHotkey
        )
    }

    pub fn from_tool_name(value: &str) -> Option<Self> {
        [
            Self::DesktopCapabilities,
            Self::DesktopPermissions,
            Self::SessionOpen,
            Self::SessionClose,
            Self::AppList,
            Self::AppLaunch,
            Self::AppQuit,
            Self::WindowList,
            Self::WindowFocus,
            Self::WindowMove,
            Self::WindowResize,
            Self::ObserveCapture,
            Self::OcrRead,
            Self::VisionDescribe,
            Self::VisionLocate,
            Self::InputClick,
            Self::InputType,
            Self::InputHotkey,
        ]
        .into_iter()
        .find(|capability| capability.tool_name() == value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coordinate {
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundingBox {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSelector {
    pub app: Option<String>,
    pub window: Option<String>,
    pub screen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPolicy {
    pub capabilities: BTreeSet<Capability>,
    pub allowed_apps: Vec<String>,
    pub allowed_windows: Vec<String>,
    pub allowed_screens: Vec<String>,
    pub allow_raw_input: bool,
    pub dry_run: bool,
    pub max_actions_per_minute: usize,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            capabilities: BTreeSet::new(),
            allowed_apps: Vec::new(),
            allowed_windows: Vec::new(),
            allowed_screens: Vec::new(),
            allow_raw_input: false,
            dry_run: false,
            max_actions_per_minute: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub policy: SessionPolicy,
}

impl Session {
    pub fn new(policy: SessionPolicy, ttl: Duration) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            created_at: now,
            expires_at: now + ttl,
            policy,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

#[derive(Debug, Clone)]
pub struct CapabilityRequest {
    pub capability: Capability,
    pub trace_id: String,
    pub session_id: Option<Uuid>,
    pub target: Option<TargetSelector>,
    pub raw_coordinates: Option<Coordinate>,
}

impl CapabilityRequest {
    pub fn new(capability: Capability) -> Self {
        Self {
            capability,
            trace_id: DEFAULT_TRACE_ID.to_string(),
            session_id: None,
            target: None,
            raw_coordinates: None,
        }
    }

    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = trace_id.into();
        self
    }

    pub fn with_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_target(mut self, target: TargetSelector) -> Self {
        self.target = Some(target);
        self
    }

    pub fn with_raw_coordinates(mut self, x: i32, y: i32) -> Self {
        self.raw_coordinates = Some(Coordinate { x, y });
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub trace_id: String,
    pub matched_rule: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolErrorCode {
    Validation,
    PolicyDenied,
    SessionRequired,
    SessionExpired,
    RateLimited,
    Unsupported,
    NotFound,
    Internal,
}

#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[error("{code:?}: {message} [{trace_id}]")]
pub struct ToolError {
    pub code: ToolErrorCode,
    pub message: String,
    pub trace_id: String,
}

impl ToolError {
    pub fn new(
        code: ToolErrorCode,
        message: impl Into<String>,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            trace_id: trace_id.into(),
        }
    }

    pub fn validation(message: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self::new(ToolErrorCode::Validation, message, trace_id)
    }

    pub fn policy_denied(message: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self::new(ToolErrorCode::PolicyDenied, message, trace_id)
    }

    pub fn session_required(trace_id: impl Into<String>) -> Self {
        Self::new(
            ToolErrorCode::SessionRequired,
            "This action requires an active session.",
            trace_id,
        )
    }

    pub fn session_expired(trace_id: impl Into<String>) -> Self {
        Self::new(
            ToolErrorCode::SessionExpired,
            "The referenced session has expired.",
            trace_id,
        )
    }

    pub fn rate_limited(trace_id: impl Into<String>) -> Self {
        Self::new(
            ToolErrorCode::RateLimited,
            "The session action budget has been exhausted.",
            trace_id,
        )
    }

    pub fn unsupported(message: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self::new(ToolErrorCode::Unsupported, message, trace_id)
    }

    pub fn not_found(message: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self::new(ToolErrorCode::NotFound, message, trace_id)
    }

    pub fn internal(message: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self::new(ToolErrorCode::Internal, message, trace_id)
    }
}

#[derive(Debug, Default)]
pub struct PolicyEngine {
    action_windows: Mutex<HashMap<Uuid, Vec<DateTime<Utc>>>>,
}

impl PolicyEngine {
    pub fn evaluate(
        &self,
        session: Option<&Session>,
        request: &CapabilityRequest,
    ) -> Result<PolicyDecision, ToolError> {
        if request.capability.requires_session() && session.is_none() {
            return Err(ToolError::session_required(&request.trace_id));
        }

        if let Some(session) = session {
            if session.is_expired() {
                return Err(ToolError::session_expired(&request.trace_id));
            }

            if request.capability.requires_session()
                && !session.policy.capabilities.contains(&request.capability)
            {
                return Err(ToolError::policy_denied(
                    format!(
                        "Capability {} is not allowed by the active session policy.",
                        request.capability.tool_name()
                    ),
                    &request.trace_id,
                ));
            }

            self.check_allowlists(session, request)?;
            self.check_coordinate_policy(session, request)?;
            self.check_rate_limit(session, request)?;

            return Ok(PolicyDecision {
                allowed: true,
                trace_id: request.trace_id.clone(),
                matched_rule: "session_allowlist".to_string(),
            });
        }

        Ok(PolicyDecision {
            allowed: true,
            trace_id: request.trace_id.clone(),
            matched_rule: "observation_without_session".to_string(),
        })
    }

    fn check_allowlists(
        &self,
        session: &Session,
        request: &CapabilityRequest,
    ) -> Result<(), ToolError> {
        let Some(target) = &request.target else {
            return Ok(());
        };

        if let Some(app) = &target.app
            && !session.policy.allowed_apps.is_empty()
            && !session.policy.allowed_apps.iter().any(|item| item == app)
        {
            return Err(ToolError::policy_denied(
                format!("The requested target is outside the allowed app list: {app}"),
                &request.trace_id,
            ));
        }

        if let Some(window) = &target.window
            && !session.policy.allowed_windows.is_empty()
            && !session
                .policy
                .allowed_windows
                .iter()
                .any(|item| item == window)
        {
            return Err(ToolError::policy_denied(
                format!("The requested target is outside the allowed window list: {window}"),
                &request.trace_id,
            ));
        }

        if let Some(screen) = &target.screen
            && !session.policy.allowed_screens.is_empty()
            && !session
                .policy
                .allowed_screens
                .iter()
                .any(|item| item == screen)
        {
            return Err(ToolError::policy_denied(
                format!("The requested target is outside the allowed screen list: {screen}"),
                &request.trace_id,
            ));
        }

        Ok(())
    }

    fn check_coordinate_policy(
        &self,
        session: &Session,
        request: &CapabilityRequest,
    ) -> Result<(), ToolError> {
        if request.raw_coordinates.is_some() && !session.policy.allow_raw_input {
            return Err(ToolError::policy_denied(
                "Raw coordinates are disabled by the active session policy.",
                &request.trace_id,
            ));
        }

        Ok(())
    }

    fn check_rate_limit(
        &self,
        session: &Session,
        request: &CapabilityRequest,
    ) -> Result<(), ToolError> {
        if !request.capability.requires_session() || session.policy.max_actions_per_minute == 0 {
            return Ok(());
        }

        let now = Utc::now();
        let window_start = now - Duration::minutes(1);
        let mut action_windows = self
            .action_windows
            .lock()
            .expect("policy engine mutex must not be poisoned");
        let session_window = action_windows.entry(session.id).or_default();
        session_window.retain(|timestamp| *timestamp >= window_start);

        if session_window.len() >= session.policy.max_actions_per_minute {
            return Err(ToolError::rate_limited(&request.trace_id));
        }

        session_window.push(now);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPayloadKind {
    None,
    Preview,
    SensitiveHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPayload {
    pub kind: AuditPayloadKind,
    pub preview: Option<String>,
    pub sha256: Option<String>,
}

impl AuditPayload {
    pub fn none() -> Self {
        Self {
            kind: AuditPayloadKind::None,
            preview: None,
            sha256: None,
        }
    }

    pub fn from_preview(preview: impl Into<String>) -> Self {
        Self {
            kind: AuditPayloadKind::Preview,
            preview: Some(preview.into()),
            sha256: None,
        }
    }

    pub fn from_sensitive_bytes(bytes: &[u8]) -> Self {
        Self {
            kind: AuditPayloadKind::SensitiveHash,
            preview: None,
            sha256: Some(hash_bytes(bytes)),
        }
    }

    pub fn from_sensitive_text(value: impl AsRef<str>) -> Self {
        Self::from_sensitive_bytes(value.as_ref().as_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub trace_id: String,
    pub timestamp: DateTime<Utc>,
    pub capability: Capability,
    pub decision: String,
    pub session_id: Option<Uuid>,
    pub payload: AuditPayload,
}

impl AuditEvent {
    pub fn new(
        trace_id: impl Into<String>,
        capability: Capability,
        decision: impl Into<String>,
        session_id: Option<Uuid>,
        payload: AuditPayload,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            trace_id: trace_id.into(),
            timestamp: Utc::now(),
            capability,
            decision: decision.into(),
            session_id,
            payload,
        }
    }
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCapability {
    pub capability: Capability,
    pub supported: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionState {
    Granted,
    Denied,
    NotChecked,
    NotSupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionStatus {
    pub name: String,
    pub state: PermissionState,
    pub required_for: Vec<Capability>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDescriptor {
    pub name: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowDescriptor {
    pub id: String,
    pub title: String,
    pub app_name: Option<String>,
    pub position: Option<Coordinate>,
    pub size: Option<Size>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationArtifact {
    pub id: Uuid,
    pub path: String,
    pub sha256: String,
    pub mime_type: String,
    pub bytes: usize,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisionTarget {
    pub id: Uuid,
    pub label: String,
    pub bbox: BoundingBox,
    pub confidence: f32,
    pub artifact_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostRequest {
    GetCapabilities {
        trace_id: String,
    },
    GetPermissions {
        trace_id: String,
    },
    OpenSession {
        trace_id: String,
        policy: SessionPolicy,
    },
    CloseSession {
        trace_id: String,
        session_id: Uuid,
    },
    ListApps {
        trace_id: String,
    },
    LaunchApp {
        trace_id: String,
        session_id: Uuid,
        app: String,
    },
    QuitApp {
        trace_id: String,
        session_id: Uuid,
        app: String,
    },
    ListWindows {
        trace_id: String,
    },
    FocusWindow {
        trace_id: String,
        session_id: Uuid,
        title: String,
    },
    MoveWindow {
        trace_id: String,
        session_id: Uuid,
        title: String,
        x: i32,
        y: i32,
    },
    ResizeWindow {
        trace_id: String,
        session_id: Uuid,
        title: String,
        width: u32,
        height: u32,
    },
    Capture {
        trace_id: String,
        screen: Option<String>,
    },
    ReadOcr {
        trace_id: String,
        artifact_id: Uuid,
    },
    VisionDescribe {
        trace_id: String,
        artifact_id: Uuid,
        prompt: Option<String>,
    },
    VisionLocate {
        trace_id: String,
        artifact_id: Uuid,
        query: String,
    },
    Click {
        trace_id: String,
        session_id: Uuid,
        target_ref: Option<Uuid>,
        coordinates: Option<Coordinate>,
    },
    TypeText {
        trace_id: String,
        session_id: Uuid,
        text: String,
    },
    Hotkey {
        trace_id: String,
        session_id: Uuid,
        keys: Vec<String>,
    },
}

impl HostRequest {
    pub fn trace_id(&self) -> &str {
        match self {
            Self::GetCapabilities { trace_id }
            | Self::GetPermissions { trace_id }
            | Self::OpenSession { trace_id, .. }
            | Self::CloseSession { trace_id, .. }
            | Self::ListApps { trace_id }
            | Self::LaunchApp { trace_id, .. }
            | Self::QuitApp { trace_id, .. }
            | Self::ListWindows { trace_id }
            | Self::FocusWindow { trace_id, .. }
            | Self::MoveWindow { trace_id, .. }
            | Self::ResizeWindow { trace_id, .. }
            | Self::Capture { trace_id, .. }
            | Self::ReadOcr { trace_id, .. }
            | Self::VisionDescribe { trace_id, .. }
            | Self::VisionLocate { trace_id, .. }
            | Self::Click { trace_id, .. }
            | Self::TypeText { trace_id, .. }
            | Self::Hotkey { trace_id, .. } => trace_id,
        }
    }

    pub fn session_id(&self) -> Option<Uuid> {
        match self {
            Self::CloseSession { session_id, .. }
            | Self::LaunchApp { session_id, .. }
            | Self::QuitApp { session_id, .. }
            | Self::FocusWindow { session_id, .. }
            | Self::MoveWindow { session_id, .. }
            | Self::ResizeWindow { session_id, .. }
            | Self::Click { session_id, .. }
            | Self::TypeText { session_id, .. }
            | Self::Hotkey { session_id, .. } => Some(*session_id),
            _ => None,
        }
    }

    pub fn capability(&self) -> Capability {
        match self {
            Self::GetCapabilities { .. } => Capability::DesktopCapabilities,
            Self::GetPermissions { .. } => Capability::DesktopPermissions,
            Self::OpenSession { .. } => Capability::SessionOpen,
            Self::CloseSession { .. } => Capability::SessionClose,
            Self::ListApps { .. } => Capability::AppList,
            Self::LaunchApp { .. } => Capability::AppLaunch,
            Self::QuitApp { .. } => Capability::AppQuit,
            Self::ListWindows { .. } => Capability::WindowList,
            Self::FocusWindow { .. } => Capability::WindowFocus,
            Self::MoveWindow { .. } => Capability::WindowMove,
            Self::ResizeWindow { .. } => Capability::WindowResize,
            Self::Capture { .. } => Capability::ObserveCapture,
            Self::ReadOcr { .. } => Capability::OcrRead,
            Self::VisionDescribe { .. } => Capability::VisionDescribe,
            Self::VisionLocate { .. } => Capability::VisionLocate,
            Self::Click { .. } => Capability::InputClick,
            Self::TypeText { .. } => Capability::InputType,
            Self::Hotkey { .. } => Capability::InputHotkey,
        }
    }

    pub fn to_policy_request(&self) -> CapabilityRequest {
        let trace_id = self.trace_id().to_string();
        match self {
            Self::LaunchApp {
                session_id, app, ..
            }
            | Self::QuitApp {
                session_id, app, ..
            } => CapabilityRequest::new(self.capability())
                .with_trace_id(trace_id)
                .with_session(*session_id)
                .with_target(TargetSelector {
                    app: Some(app.clone()),
                    window: None,
                    screen: None,
                }),
            Self::FocusWindow {
                session_id, title, ..
            } => CapabilityRequest::new(self.capability())
                .with_trace_id(trace_id)
                .with_session(*session_id)
                .with_target(TargetSelector {
                    app: None,
                    window: Some(title.clone()),
                    screen: None,
                }),
            Self::MoveWindow {
                session_id, title, ..
            }
            | Self::ResizeWindow {
                session_id, title, ..
            } => CapabilityRequest::new(self.capability())
                .with_trace_id(trace_id)
                .with_session(*session_id)
                .with_target(TargetSelector {
                    app: None,
                    window: Some(title.clone()),
                    screen: None,
                }),
            Self::Capture { screen, .. } => CapabilityRequest::new(self.capability())
                .with_trace_id(trace_id)
                .with_target(TargetSelector {
                    app: None,
                    window: None,
                    screen: screen.clone(),
                }),
            Self::Click {
                session_id,
                coordinates,
                ..
            } => {
                let request = CapabilityRequest::new(self.capability())
                    .with_trace_id(trace_id)
                    .with_session(*session_id);
                if let Some(coordinates) = coordinates {
                    request.with_raw_coordinates(coordinates.x, coordinates.y)
                } else {
                    request
                }
            }
            Self::TypeText { session_id, .. } | Self::Hotkey { session_id, .. } => {
                CapabilityRequest::new(self.capability())
                    .with_trace_id(trace_id)
                    .with_session(*session_id)
            }
            Self::CloseSession {
                session_id,
                trace_id,
            } => CapabilityRequest::new(self.capability())
                .with_trace_id(trace_id.clone())
                .with_session(*session_id),
            _ => CapabilityRequest::new(self.capability()).with_trace_id(trace_id),
        }
    }

    pub fn audit_payload(&self) -> AuditPayload {
        match self {
            Self::LaunchApp { app, .. } | Self::QuitApp { app, .. } => {
                AuditPayload::from_sensitive_text(format!("app={app}"))
            }
            Self::FocusWindow { title, .. }
            | Self::MoveWindow { title, .. }
            | Self::ResizeWindow { title, .. } => {
                AuditPayload::from_sensitive_text(format!("window={title}"))
            }
            Self::Capture { screen, .. } => AuditPayload::from_preview(format!(
                "screen={}",
                screen.clone().unwrap_or_else(|| "primary".to_string())
            )),
            Self::ReadOcr { artifact_id, .. }
            | Self::VisionDescribe { artifact_id, .. }
            | Self::VisionLocate { artifact_id, .. } => {
                AuditPayload::from_preview(format!("artifact_id={artifact_id}"))
            }
            Self::Click {
                target_ref,
                coordinates,
                ..
            } => {
                if let Some(target_ref) = target_ref {
                    AuditPayload::from_preview(format!("target_ref={target_ref}"))
                } else if let Some(coordinates) = coordinates {
                    AuditPayload::from_sensitive_text(format!(
                        "raw=({}, {})",
                        coordinates.x, coordinates.y
                    ))
                } else {
                    AuditPayload::none()
                }
            }
            Self::TypeText { text, .. } => AuditPayload::from_sensitive_bytes(text.as_bytes()),
            Self::Hotkey { keys, .. } => AuditPayload::from_sensitive_text(keys.join("+")),
            _ => AuditPayload::none(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostResponse {
    Capabilities {
        platform: String,
        capabilities: Vec<BackendCapability>,
    },
    Permissions {
        platform: String,
        permissions: Vec<PermissionStatus>,
    },
    SessionOpened {
        session: Session,
    },
    SessionClosed {
        session_id: Uuid,
    },
    AppList {
        apps: Vec<AppDescriptor>,
    },
    WindowList {
        windows: Vec<WindowDescriptor>,
    },
    ArtifactCaptured {
        artifact: ObservationArtifact,
    },
    OcrRead {
        artifact_id: Uuid,
        text: String,
    },
    VisionDescription {
        artifact_id: Uuid,
        summary: String,
    },
    VisionLocated {
        target: VisionTarget,
    },
    ActionCompleted {
        trace_id: String,
        audit_event_id: Uuid,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HostEnvelope {
    Ok { response: HostResponse },
    Err { error: ToolError },
}
