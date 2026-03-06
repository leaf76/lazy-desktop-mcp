use desktop_core::{
    AppDescriptor, BackendCapability, Capability, Coordinate, HostRequest, HostResponse,
    PermissionState, PermissionStatus, SessionPolicy, ToolError, ToolErrorCode, WindowDescriptor,
};
use desktop_host::{
    ApprovalBroker, ApprovalDecision, ApprovalRequest, FakePlatformBackend, HostSecurityPolicy,
    HostService, HostServiceConfig, PlatformBackend,
};
use rusqlite::Connection;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

#[derive(Clone)]
struct RecordingApprovalBroker {
    decisions: Arc<Mutex<Vec<ApprovalDecision>>>,
    requests: Arc<Mutex<Vec<ApprovalRequest>>>,
}

impl RecordingApprovalBroker {
    fn allowing() -> Self {
        Self {
            decisions: Arc::new(Mutex::new(vec![ApprovalDecision::AllowPersist])),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn denying() -> Self {
        Self {
            decisions: Arc::new(Mutex::new(vec![ApprovalDecision::Deny])),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("requests").len()
    }
}

impl ApprovalBroker for RecordingApprovalBroker {
    fn request(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ToolError> {
        self.requests
            .lock()
            .expect("requests")
            .push(request.clone());
        Ok(self.decisions.lock().expect("decisions").remove(0))
    }
}

#[derive(Debug, Clone, Default)]
struct ScriptedBackendState {
    focused_windows: Vec<String>,
    moved_windows: Vec<(String, Coordinate)>,
    resized_windows: Vec<(String, u32, u32)>,
    clicks: Vec<Coordinate>,
    typed_texts: Vec<String>,
    hotkeys: Vec<Vec<String>>,
}

#[derive(Clone)]
struct ScriptedBackend {
    capabilities: Vec<BackendCapability>,
    permissions: Vec<PermissionStatus>,
    windows: Vec<WindowDescriptor>,
    apps: Vec<AppDescriptor>,
    state: Arc<Mutex<ScriptedBackendState>>,
}

impl ScriptedBackend {
    fn with_capabilities(capabilities: Vec<BackendCapability>) -> Self {
        Self {
            capabilities,
            permissions: Vec::new(),
            windows: vec![WindowDescriptor {
                id: "window-1".to_string(),
                title: "Editor".to_string(),
                app_name: Some("TextEdit".to_string()),
                position: Some(Coordinate { x: 32, y: 48 }),
                size: Some(desktop_core::Size {
                    width: 640,
                    height: 480,
                }),
            }],
            apps: vec![AppDescriptor {
                name: "TextEdit".to_string(),
                pid: Some(42),
            }],
            state: Arc::new(Mutex::new(ScriptedBackendState::default())),
        }
    }

    fn with_permissions(mut self, permissions: Vec<PermissionStatus>) -> Self {
        self.permissions = permissions;
        self
    }

    fn state(&self) -> Arc<Mutex<ScriptedBackendState>> {
        Arc::clone(&self.state)
    }
}

impl PlatformBackend for ScriptedBackend {
    fn platform_name(&self) -> &'static str {
        "macos"
    }

    fn capabilities(&self) -> Vec<BackendCapability> {
        self.capabilities.clone()
    }

    fn permission_statuses(&self) -> Vec<PermissionStatus> {
        self.permissions.clone()
    }

    fn list_apps(&mut self, _trace_id: &str) -> Result<Vec<AppDescriptor>, ToolError> {
        Ok(self.apps.clone())
    }

    fn list_windows(&mut self, _trace_id: &str) -> Result<Vec<WindowDescriptor>, ToolError> {
        Ok(self.windows.clone())
    }

    fn focus_window(&mut self, title: &str, _trace_id: &str) -> Result<String, ToolError> {
        self.state
            .lock()
            .expect("state")
            .focused_windows
            .push(title.to_string());
        Ok(format!("Focused {title}."))
    }

    fn move_window(
        &mut self,
        title: &str,
        coordinate: Coordinate,
        _trace_id: &str,
    ) -> Result<String, ToolError> {
        self.state
            .lock()
            .expect("state")
            .moved_windows
            .push((title.to_string(), coordinate.clone()));
        Ok(format!("Moved {title}."))
    }

    fn resize_window(
        &mut self,
        title: &str,
        width: u32,
        height: u32,
        _trace_id: &str,
    ) -> Result<String, ToolError> {
        self.state
            .lock()
            .expect("state")
            .resized_windows
            .push((title.to_string(), width, height));
        Ok(format!("Resized {title}."))
    }

    fn capture(
        &mut self,
        _screen: Option<&str>,
        output_path: &Path,
        _trace_id: &str,
    ) -> Result<(), ToolError> {
        fs::write(output_path, b"fake-image-bytes").expect("artifact");
        Ok(())
    }

    fn click(&mut self, coordinate: Coordinate, _trace_id: &str) -> Result<String, ToolError> {
        self.state.lock().expect("state").clicks.push(coordinate);
        Ok("Clicked.".to_string())
    }

    fn type_text(&mut self, text: &str, _trace_id: &str) -> Result<String, ToolError> {
        self.state
            .lock()
            .expect("state")
            .typed_texts
            .push(text.to_string());
        Ok("Typed.".to_string())
    }

    fn hotkey(&mut self, keys: &[String], _trace_id: &str) -> Result<String, ToolError> {
        self.state
            .lock()
            .expect("state")
            .hotkeys
            .push(keys.to_vec());
        Ok("Pressed hotkey.".to_string())
    }
}

fn capability(capability: Capability, supported: bool, reason: Option<&str>) -> BackendCapability {
    BackendCapability {
        capability,
        supported,
        reason: reason.map(ToString::to_string),
    }
}

fn permission(
    name: &str,
    state: PermissionState,
    required_for: Vec<Capability>,
    details: &str,
) -> PermissionStatus {
    PermissionStatus {
        name: name.to_string(),
        state,
        required_for,
        details: details.to_string(),
    }
}

fn write_executable_script(path: &Path, body: &str) {
    fs::write(path, body).expect("script");
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod");
}

#[tokio::test]
async fn opens_session_and_launches_allowed_app() {
    let tempdir = tempdir().expect("tempdir");
    let backend = FakePlatformBackend::default();
    let mut service = HostService::new(backend, HostServiceConfig::for_test(tempdir.path()))
        .await
        .expect("service");

    let open_response = service
        .handle(HostRequest::OpenSession {
            trace_id: "trace-open".to_string(),
            policy: SessionPolicy {
                capabilities: BTreeSet::from([Capability::AppLaunch]),
                allowed_apps: vec!["TextEdit".to_string()],
                allowed_windows: Vec::new(),
                allowed_screens: Vec::new(),
                allow_raw_input: false,
                dry_run: false,
                max_actions_per_minute: 10,
            },
        })
        .await
        .expect("open session");

    let session_id = match open_response {
        HostResponse::SessionOpened { session } => session.id,
        other => panic!("unexpected response: {other:?}"),
    };

    let launch_response = service
        .handle(HostRequest::LaunchApp {
            trace_id: "trace-launch".to_string(),
            session_id,
            app: "TextEdit".to_string(),
        })
        .await
        .expect("launch app");

    match launch_response {
        HostResponse::ActionCompleted { message, .. } => {
            assert!(message.contains("TextEdit"));
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn rejects_app_launch_outside_allowlist() {
    let tempdir = tempdir().expect("tempdir");
    let backend = FakePlatformBackend::default();
    let mut service = HostService::new(backend, HostServiceConfig::for_test(tempdir.path()))
        .await
        .expect("service");

    let open_response = service
        .handle(HostRequest::OpenSession {
            trace_id: "trace-open".to_string(),
            policy: SessionPolicy {
                capabilities: BTreeSet::from([Capability::AppLaunch]),
                allowed_apps: vec!["TextEdit".to_string()],
                allowed_windows: Vec::new(),
                allowed_screens: Vec::new(),
                allow_raw_input: false,
                dry_run: false,
                max_actions_per_minute: 10,
            },
        })
        .await
        .expect("open session");

    let session_id = match open_response {
        HostResponse::SessionOpened { session } => session.id,
        other => panic!("unexpected response: {other:?}"),
    };

    let error = service
        .handle(HostRequest::LaunchApp {
            trace_id: "trace-launch".to_string(),
            session_id,
            app: "Calculator".to_string(),
        })
        .await
        .expect_err("disallowed app must be denied");

    assert_eq!(error.code, ToolErrorCode::PolicyDenied);
}

#[tokio::test]
async fn rejects_session_capabilities_not_enabled_by_host_policy() {
    let tempdir = tempdir().expect("tempdir");
    let backend = FakePlatformBackend::default();
    let config = HostServiceConfig::for_test(tempdir.path())
        .with_security_policy(HostSecurityPolicy::default());
    let mut service = HostService::new(backend, config).await.expect("service");

    let error = service
        .handle(HostRequest::OpenSession {
            trace_id: "trace-open".to_string(),
            policy: SessionPolicy {
                capabilities: BTreeSet::from([Capability::AppLaunch]),
                allowed_apps: vec!["TextEdit".to_string()],
                allowed_windows: Vec::new(),
                allowed_screens: Vec::new(),
                allow_raw_input: false,
                dry_run: false,
                max_actions_per_minute: 10,
            },
        })
        .await
        .expect_err("host policy should reject session capability");

    assert_eq!(error.code, ToolErrorCode::PolicyDenied);
}

#[tokio::test]
async fn approves_out_of_policy_app_launch_and_persists_overlay() {
    let tempdir = tempdir().expect("tempdir");
    let backend = FakePlatformBackend::default();
    let broker = RecordingApprovalBroker::allowing();
    let mut service = HostService::new(backend, HostServiceConfig::for_test(tempdir.path()))
        .await
        .expect("service")
        .with_approval_broker(broker.clone());

    let open_response = service
        .handle(HostRequest::OpenSession {
            trace_id: "trace-open".to_string(),
            policy: SessionPolicy {
                capabilities: BTreeSet::from([Capability::AppLaunch]),
                allowed_apps: vec!["TextEdit".to_string()],
                allowed_windows: Vec::new(),
                allowed_screens: Vec::new(),
                allow_raw_input: false,
                dry_run: false,
                max_actions_per_minute: 10,
            },
        })
        .await
        .expect("open session");

    let session_id = match open_response {
        HostResponse::SessionOpened { session } => session.id,
        other => panic!("unexpected response: {other:?}"),
    };

    let launch_response = service
        .handle(HostRequest::LaunchApp {
            trace_id: "trace-launch".to_string(),
            session_id,
            app: "Calculator".to_string(),
        })
        .await
        .expect("approved launch");

    match launch_response {
        HostResponse::ActionCompleted { message, .. } => {
            assert!(message.contains("Calculator"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert_eq!(broker.request_count(), 1);

    let overlay = std::fs::read_to_string(tempdir.path().join("policy-overlay.json"))
        .expect("overlay policy must be persisted");
    assert!(overlay.contains("Calculator"));

    let connection = Connection::open(tempdir.path().join("audit.db")).expect("audit db");
    let (decision, preview, sha256): (String, Option<String>, Option<String>) = connection
        .query_row(
            "SELECT decision, payload_preview, payload_sha256
             FROM audit_events
             WHERE decision LIKE 'approval_%'
             ORDER BY timestamp DESC
             LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("approval audit row");

    assert_eq!(decision, "approval_allowed_persisted");
    assert_eq!(preview.as_deref(), Some("target_kind=app persisted=true"));
    assert!(sha256.is_some());
    assert!(!overlay.contains("payload_sha256"));
}

#[tokio::test]
async fn denies_out_of_policy_app_launch_when_user_denies() {
    let tempdir = tempdir().expect("tempdir");
    let backend = FakePlatformBackend::default();
    let broker = RecordingApprovalBroker::denying();
    let mut service = HostService::new(backend, HostServiceConfig::for_test(tempdir.path()))
        .await
        .expect("service")
        .with_approval_broker(broker.clone());

    let open_response = service
        .handle(HostRequest::OpenSession {
            trace_id: "trace-open".to_string(),
            policy: SessionPolicy {
                capabilities: BTreeSet::from([Capability::AppLaunch]),
                allowed_apps: vec!["TextEdit".to_string()],
                allowed_windows: Vec::new(),
                allowed_screens: Vec::new(),
                allow_raw_input: false,
                dry_run: false,
                max_actions_per_minute: 10,
            },
        })
        .await
        .expect("open session");

    let session_id = match open_response {
        HostResponse::SessionOpened { session } => session.id,
        other => panic!("unexpected response: {other:?}"),
    };

    let error = service
        .handle(HostRequest::LaunchApp {
            trace_id: "trace-launch".to_string(),
            session_id,
            app: "Calculator".to_string(),
        })
        .await
        .expect_err("user denial must fail");

    assert_eq!(error.code, ToolErrorCode::PolicyDenied);
    assert_eq!(broker.request_count(), 1);
    assert!(!tempdir.path().join("policy-overlay.json").exists());
}

#[tokio::test]
async fn approves_requested_screen_during_session_open() {
    let tempdir = tempdir().expect("tempdir");
    let backend = FakePlatformBackend::default();
    let broker = RecordingApprovalBroker::allowing();
    let mut service = HostService::new(backend, HostServiceConfig::for_test(tempdir.path()))
        .await
        .expect("service")
        .with_approval_broker(broker.clone());

    let response = service
        .handle(HostRequest::OpenSession {
            trace_id: "trace-open".to_string(),
            policy: SessionPolicy {
                capabilities: BTreeSet::from([Capability::InputType]),
                allowed_apps: Vec::new(),
                allowed_windows: Vec::new(),
                allowed_screens: vec!["secondary".to_string()],
                allow_raw_input: false,
                dry_run: false,
                max_actions_per_minute: 10,
            },
        })
        .await
        .expect("session with approved screen");

    let session = match response {
        HostResponse::SessionOpened { session } => session,
        other => panic!("unexpected response: {other:?}"),
    };

    assert_eq!(
        session.policy.allowed_screens,
        vec!["secondary".to_string()]
    );
    assert_eq!(broker.request_count(), 1);
    let overlay =
        std::fs::read_to_string(tempdir.path().join("policy-overlay.json")).expect("overlay");
    assert!(overlay.contains("secondary"));
}

#[tokio::test]
async fn does_not_elevate_session_capability_via_runtime_approval() {
    let tempdir = tempdir().expect("tempdir");
    let backend = FakePlatformBackend::default();
    let broker = RecordingApprovalBroker::allowing();
    let config = HostServiceConfig::for_test(tempdir.path())
        .with_security_policy(HostSecurityPolicy::default());
    let mut service = HostService::new(backend, config)
        .await
        .expect("service")
        .with_approval_broker(broker.clone());

    let error = service
        .handle(HostRequest::OpenSession {
            trace_id: "trace-open".to_string(),
            policy: SessionPolicy {
                capabilities: BTreeSet::from([Capability::AppLaunch]),
                allowed_apps: vec!["Calculator".to_string()],
                allowed_windows: Vec::new(),
                allowed_screens: Vec::new(),
                allow_raw_input: false,
                dry_run: false,
                max_actions_per_minute: 10,
            },
        })
        .await
        .expect_err("capability elevation must be denied");

    assert_eq!(error.code, ToolErrorCode::PolicyDenied);
    assert_eq!(broker.request_count(), 0);
}

#[tokio::test]
async fn executes_window_and_input_actions_when_backend_supports_them() {
    let tempdir = tempdir().expect("tempdir");
    let backend = ScriptedBackend::with_capabilities(vec![
        capability(Capability::WindowFocus, true, None),
        capability(Capability::InputClick, true, None),
        capability(Capability::InputType, true, None),
        capability(Capability::InputHotkey, true, None),
    ])
    .with_permissions(vec![permission(
        "accessibility",
        PermissionState::Granted,
        vec![
            Capability::WindowFocus,
            Capability::InputClick,
            Capability::InputType,
            Capability::InputHotkey,
        ],
        "Accessibility permission is available.",
    )]);
    let state = backend.state();
    let security_policy = HostSecurityPolicy {
        allow_raw_input: true,
        ..HostSecurityPolicy::for_test()
    };
    let config = HostServiceConfig::for_test(tempdir.path()).with_security_policy(security_policy);
    let mut service = HostService::new(backend, config).await.expect("service");

    let open_response = service
        .handle(HostRequest::OpenSession {
            trace_id: "trace-open".to_string(),
            policy: SessionPolicy {
                capabilities: BTreeSet::from([
                    Capability::WindowFocus,
                    Capability::InputClick,
                    Capability::InputType,
                    Capability::InputHotkey,
                ]),
                allowed_apps: Vec::new(),
                allowed_windows: vec!["Editor".to_string()],
                allowed_screens: vec!["primary".to_string()],
                allow_raw_input: true,
                dry_run: false,
                max_actions_per_minute: 10,
            },
        })
        .await
        .expect("open session");

    let session_id = match open_response {
        HostResponse::SessionOpened { session } => session.id,
        other => panic!("unexpected response: {other:?}"),
    };

    service
        .handle(HostRequest::FocusWindow {
            trace_id: "trace-focus".to_string(),
            session_id,
            title: "Editor".to_string(),
        })
        .await
        .expect("focus window");
    service
        .handle(HostRequest::TypeText {
            trace_id: "trace-type".to_string(),
            session_id,
            text: "hello".to_string(),
        })
        .await
        .expect("type text");
    service
        .handle(HostRequest::Hotkey {
            trace_id: "trace-hotkey".to_string(),
            session_id,
            keys: vec!["Control".to_string(), "Shift".to_string(), "P".to_string()],
        })
        .await
        .expect("hotkey");
    service
        .handle(HostRequest::Click {
            trace_id: "trace-click".to_string(),
            session_id,
            target_ref: None,
            coordinates: Some(Coordinate { x: 80, y: 120 }),
        })
        .await
        .expect("click");

    let state = state.lock().expect("state");
    assert_eq!(state.focused_windows, vec!["Editor".to_string()]);
    assert_eq!(state.typed_texts, vec!["hello".to_string()]);
    assert_eq!(
        state.hotkeys,
        vec![vec![
            "Control".to_string(),
            "Shift".to_string(),
            "P".to_string()
        ]]
    );
    assert_eq!(state.clicks, vec![Coordinate { x: 80, y: 120 }]);
}

#[tokio::test]
async fn rejects_session_open_for_backend_unsupported_capability() {
    let tempdir = tempdir().expect("tempdir");
    let backend = ScriptedBackend::with_capabilities(vec![capability(
        Capability::InputType,
        false,
        Some("Accessibility permission is required before enabling keyboard input."),
    )]);
    let config = HostServiceConfig::for_test(tempdir.path());
    let mut service = HostService::new(backend, config).await.expect("service");

    let error = service
        .handle(HostRequest::OpenSession {
            trace_id: "trace-open".to_string(),
            policy: SessionPolicy {
                capabilities: BTreeSet::from([Capability::InputType]),
                allowed_apps: Vec::new(),
                allowed_windows: Vec::new(),
                allowed_screens: vec!["primary".to_string()],
                allow_raw_input: false,
                dry_run: false,
                max_actions_per_minute: 10,
            },
        })
        .await
        .expect_err("unsupported capability must fail during session open");

    assert_eq!(error.code, ToolErrorCode::Unsupported);
    assert!(error.message.contains("Accessibility permission"));
}

#[tokio::test]
async fn reports_capabilities_after_backend_and_policy_filtering() {
    let tempdir = tempdir().expect("tempdir");
    let backend = ScriptedBackend::with_capabilities(vec![
        capability(Capability::WindowList, true, None),
        capability(
            Capability::OcrRead,
            false,
            Some("OCR requires the `tesseract` binary to be installed and available on PATH."),
        ),
        capability(Capability::InputType, true, None),
    ]);
    let security_policy = HostSecurityPolicy {
        allowed_standalone_capabilities: BTreeSet::from([Capability::WindowList]),
        ..HostSecurityPolicy::default()
    };
    let config = HostServiceConfig::for_test(tempdir.path()).with_security_policy(security_policy);
    let mut service = HostService::new(backend, config).await.expect("service");

    let response = service
        .handle(HostRequest::GetCapabilities {
            trace_id: "trace-capabilities".to_string(),
        })
        .await
        .expect("capabilities");

    let HostResponse::Capabilities { capabilities, .. } = response else {
        panic!("unexpected response: {response:?}");
    };

    let window_list = capabilities
        .iter()
        .find(|item| item.capability == Capability::WindowList)
        .expect("window list capability");
    assert!(window_list.supported);

    let ocr = capabilities
        .iter()
        .find(|item| item.capability == Capability::OcrRead)
        .expect("ocr capability");
    assert!(!ocr.supported);
    assert!(
        ocr.reason
            .as_deref()
            .expect("ocr reason")
            .contains("tesseract")
    );

    let input_type = capabilities
        .iter()
        .find(|item| item.capability == Capability::InputType)
        .expect("input type capability");
    assert!(!input_type.supported);
    assert_eq!(
        input_type.reason.as_deref(),
        Some("Disabled by the host security policy. Update policy.json to enable it.")
    );
}

#[tokio::test]
async fn reports_permission_probe_results_from_backend() {
    let tempdir = tempdir().expect("tempdir");
    let backend = ScriptedBackend::with_capabilities(vec![capability(
        Capability::ObserveCapture,
        true,
        None,
    )])
    .with_permissions(vec![
        permission(
            "accessibility",
            PermissionState::Denied,
            vec![Capability::InputType],
            "Accessibility permission is missing.",
        ),
        permission(
            "screen_recording",
            PermissionState::Granted,
            vec![Capability::ObserveCapture],
            "Screen recording permission is available.",
        ),
    ]);
    let mut service = HostService::new(backend, HostServiceConfig::for_test(tempdir.path()))
        .await
        .expect("service");

    let response = service
        .handle(HostRequest::GetPermissions {
            trace_id: "trace-permissions".to_string(),
        })
        .await
        .expect("permissions");

    let HostResponse::Permissions { permissions, .. } = response else {
        panic!("unexpected response: {response:?}");
    };

    assert_eq!(permissions.len(), 2);
    assert_eq!(permissions[0].name, "accessibility");
    assert_eq!(permissions[0].state, PermissionState::Denied);
    assert_eq!(permissions[1].name, "screen_recording");
    assert_eq!(permissions[1].state, PermissionState::Granted);
}

#[tokio::test]
async fn configured_vision_command_handles_describe_and_locate() {
    let tempdir = tempdir().expect("tempdir");
    let backend = ScriptedBackend::with_capabilities(vec![
        capability(Capability::ObserveCapture, true, None),
        capability(Capability::VisionDescribe, true, None),
        capability(Capability::VisionLocate, true, None),
    ])
    .with_permissions(vec![permission(
        "screen_recording",
        PermissionState::Granted,
        vec![
            Capability::ObserveCapture,
            Capability::VisionDescribe,
            Capability::VisionLocate,
        ],
        "Screen recording permission is available.",
    )]);
    let script_path = tempdir.path().join("vision-adapter.sh");
    write_executable_script(
        &script_path,
        r#"#!/bin/sh
payload="$(cat)"
case "$payload" in
  *'"action":"describe"'*)
    printf '{"summary":"Main window with a submit button"}'
    ;;
  *)
    printf '{"target":{"label":"Submit","bbox":{"x":10,"y":20,"width":40,"height":30},"confidence":0.95}}'
    ;;
esac
"#,
    );
    let config = HostServiceConfig::for_test(tempdir.path())
        .with_vision_command(script_path.to_string_lossy().into_owned(), Vec::new());
    let mut service = HostService::new(backend, config).await.expect("service");

    let capture = service
        .handle(HostRequest::Capture {
            trace_id: "trace-capture".to_string(),
            screen: Some("primary".to_string()),
        })
        .await
        .expect("capture");
    let artifact_id = match capture {
        HostResponse::ArtifactCaptured { artifact } => artifact.id,
        other => panic!("unexpected response: {other:?}"),
    };

    let describe = service
        .handle(HostRequest::VisionDescribe {
            trace_id: "trace-describe".to_string(),
            artifact_id,
            prompt: None,
        })
        .await
        .expect("vision describe");
    match describe {
        HostResponse::VisionDescription { summary, .. } => {
            assert!(summary.contains("submit button"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let locate = service
        .handle(HostRequest::VisionLocate {
            trace_id: "trace-locate".to_string(),
            artifact_id,
            query: "Submit".to_string(),
        })
        .await
        .expect("vision locate");
    match locate {
        HostResponse::VisionLocated { target } => {
            assert_eq!(target.label, "Submit");
            assert_eq!(target.bbox.x, 10);
            assert_eq!(target.bbox.y, 20);
            assert_eq!(target.bbox.width, 40);
            assert_eq!(target.bbox.height, 30);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn lists_windows_and_executes_interaction_actions() {
    let tempdir = tempdir().expect("tempdir");
    let backend = FakePlatformBackend::default();
    let security_policy = HostSecurityPolicy {
        allow_raw_input: true,
        ..HostSecurityPolicy::for_test()
    };
    let config = HostServiceConfig::for_test(tempdir.path()).with_security_policy(security_policy);
    let mut service = HostService::new(backend, config).await.expect("service");

    let open_response = service
        .handle(HostRequest::OpenSession {
            trace_id: "trace-open".to_string(),
            policy: SessionPolicy {
                capabilities: BTreeSet::from([
                    Capability::WindowFocus,
                    Capability::InputClick,
                    Capability::InputType,
                    Capability::InputHotkey,
                ]),
                allowed_apps: Vec::new(),
                allowed_windows: vec!["Editor".to_string()],
                allowed_screens: vec!["primary".to_string()],
                allow_raw_input: true,
                dry_run: false,
                max_actions_per_minute: 10,
            },
        })
        .await
        .expect("open session");

    let session_id = match open_response {
        HostResponse::SessionOpened { session } => session.id,
        other => panic!("unexpected response: {other:?}"),
    };

    let windows_response = service
        .handle(HostRequest::ListWindows {
            trace_id: "trace-windows".to_string(),
        })
        .await
        .expect("list windows");

    match windows_response {
        HostResponse::WindowList { windows } => {
            assert_eq!(windows.len(), 1);
            assert_eq!(windows[0].title, "Editor");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let focus_response = service
        .handle(HostRequest::FocusWindow {
            trace_id: "trace-focus".to_string(),
            session_id,
            title: "Editor".to_string(),
        })
        .await
        .expect("focus window");

    match focus_response {
        HostResponse::ActionCompleted { message, .. } => {
            assert!(message.contains("Editor"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let type_response = service
        .handle(HostRequest::TypeText {
            trace_id: "trace-type".to_string(),
            session_id,
            text: "hello desktop".to_string(),
        })
        .await
        .expect("type text");

    match type_response {
        HostResponse::ActionCompleted { message, .. } => {
            assert!(message.contains("13 characters"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let hotkey_response = service
        .handle(HostRequest::Hotkey {
            trace_id: "trace-hotkey".to_string(),
            session_id,
            keys: vec!["Command".to_string(), "Shift".to_string(), "P".to_string()],
        })
        .await
        .expect("send hotkey");

    match hotkey_response {
        HostResponse::ActionCompleted { message, .. } => {
            assert!(message.contains("Command+Shift+P"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let click_response = service
        .handle(HostRequest::Click {
            trace_id: "trace-click".to_string(),
            session_id,
            target_ref: None,
            coordinates: Some(desktop_core::Coordinate { x: 40, y: 24 }),
        })
        .await
        .expect("click with coordinates");

    match click_response {
        HostResponse::ActionCompleted { message, .. } => {
            assert!(message.contains("(40, 24)"));
        }
        other => panic!("unexpected response: {other:?}"),
    }
}
