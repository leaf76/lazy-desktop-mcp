use chrono::{Duration, Utc};
use desktop_core::{
    Capability, CapabilityRequest, PolicyEngine, Session, SessionPolicy, TargetSelector,
    ToolErrorCode,
};
use uuid::Uuid;

fn allow_all_session() -> Session {
    let now = Utc::now();

    Session {
        id: Uuid::new_v4(),
        created_at: now,
        expires_at: now + Duration::minutes(5),
        policy: SessionPolicy {
            capabilities: [
                Capability::AppLaunch,
                Capability::ObserveCapture,
                Capability::InputClick,
            ]
            .into_iter()
            .collect(),
            allowed_apps: vec!["TextEdit".to_string()],
            allowed_windows: vec!["Editor".to_string()],
            allowed_screens: vec!["primary".to_string()],
            allow_raw_input: false,
            dry_run: false,
            max_actions_per_minute: 5,
        },
    }
}

#[test]
fn mutating_capability_requires_session() {
    let engine = PolicyEngine::default();
    let request = CapabilityRequest::new(Capability::AppLaunch).with_target(TargetSelector {
        app: Some("TextEdit".to_string()),
        window: None,
        screen: None,
    });

    let error = engine
        .evaluate(None, &request)
        .expect_err("missing session must fail");

    assert_eq!(error.code, ToolErrorCode::SessionRequired);
}

#[test]
fn denies_target_outside_allowlist() {
    let engine = PolicyEngine::default();
    let session = allow_all_session();
    let request = CapabilityRequest::new(Capability::AppLaunch).with_target(TargetSelector {
        app: Some("Calculator".to_string()),
        window: None,
        screen: None,
    });

    let error = engine
        .evaluate(Some(&session), &request)
        .expect_err("disallowed app must fail");

    assert_eq!(error.code, ToolErrorCode::PolicyDenied);
    assert!(error.message.contains("allowed app"));
}

#[test]
fn denies_raw_click_when_policy_forbids_it() {
    let engine = PolicyEngine::default();
    let session = allow_all_session();
    let request = CapabilityRequest::new(Capability::InputClick)
        .with_session(session.id)
        .with_raw_coordinates(40, 80);

    let error = engine
        .evaluate(Some(&session), &request)
        .expect_err("raw coordinates must be denied");

    assert_eq!(error.code, ToolErrorCode::PolicyDenied);
}

#[test]
fn tracks_rate_limit_per_session() {
    let engine = PolicyEngine::default();
    let session = allow_all_session();
    let request = CapabilityRequest::new(Capability::AppLaunch)
        .with_session(session.id)
        .with_target(TargetSelector {
            app: Some("TextEdit".to_string()),
            window: None,
            screen: None,
        });

    for _ in 0..session.policy.max_actions_per_minute {
        engine
            .evaluate(Some(&session), &request)
            .expect("budget should remain available");
    }

    let error = engine
        .evaluate(Some(&session), &request)
        .expect_err("extra request must be rate-limited");

    assert_eq!(error.code, ToolErrorCode::RateLimited);
}

#[test]
fn observation_is_allowed_without_session() {
    let engine = PolicyEngine::default();
    let request = CapabilityRequest::new(Capability::ObserveCapture).with_target(TargetSelector {
        app: None,
        window: None,
        screen: Some("primary".to_string()),
    });

    let decision = engine
        .evaluate(None, &request)
        .expect("observation should be allowed without session");

    assert!(decision.allowed);
}
