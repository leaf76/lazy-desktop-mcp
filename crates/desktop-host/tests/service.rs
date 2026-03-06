use desktop_core::{
    Capability, HostRequest, HostResponse, SessionPolicy, ToolError, ToolErrorCode,
};
use desktop_host::{
    ApprovalBroker, ApprovalDecision, ApprovalRequest, FakePlatformBackend, HostSecurityPolicy,
    HostService, HostServiceConfig,
};
use rusqlite::Connection;
use std::collections::BTreeSet;
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
