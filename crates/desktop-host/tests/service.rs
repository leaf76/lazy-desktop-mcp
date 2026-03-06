use desktop_core::{Capability, HostRequest, HostResponse, SessionPolicy, ToolErrorCode};
use desktop_host::{FakePlatformBackend, HostSecurityPolicy, HostService, HostServiceConfig};
use std::collections::BTreeSet;
use tempfile::tempdir;

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
