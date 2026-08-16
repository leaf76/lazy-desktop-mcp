use desktop_core::{
    AppDescriptor, CaptureScope, HostPolicySnapshot, HostResponse, HostRuntimeInfo,
    ObservationArtifact, compact_host_response,
};
use uuid::Uuid;

fn empty_policy() -> HostPolicySnapshot {
    HostPolicySnapshot {
        allowed_standalone_capabilities: Vec::new(),
        allowed_session_capabilities: Vec::new(),
        allowed_apps: Vec::new(),
        allowed_windows: Vec::new(),
        allowed_screens: Vec::new(),
        allow_raw_input: false,
        max_actions_per_minute: 30,
        capture_scope: CaptureScope::Primary,
        capture_max_long_edge: 1280,
        capture_format: desktop_core::CaptureFormat::Jpeg,
        capture_retain_seconds: 300,
        ocr_max_chars: 500,
        ocr_allow_full: false,
        lists_max_items: 30,
        overlay_max_age_seconds: 86400,
    }
}

#[test]
fn compact_runtime_omits_full_paths_and_policy_snapshots() {
    let response = HostResponse::Runtime {
        runtime: Box::new(HostRuntimeInfo {
            platform: "macos".to_string(),
            security_policy_path: "/tmp/secret-dir/policy.json".to_string(),
            overlay_policy_path: "/tmp/secret-dir/policy-overlay.json".to_string(),
            audit_db_path: "/tmp/secret-dir/audit.db".to_string(),
            artifact_dir: "/tmp/secret-dir/artifacts".to_string(),
            vision_command_configured: false,
            base_policy: empty_policy(),
            effective_policy: empty_policy(),
            presence_state_path: None,
            presence_events_path: None,
            presence_stop_path: None,
            presence_pause_path: None,
            presence_ui_app_path: None,
            presence_ui_running: Some(false),
            presence_ui_auto_launch: None,
            presence_ui_auto_quit: None,
        }),
    };

    let compact = compact_host_response(&response);
    assert_eq!(compact["kind"], "runtime");
    assert_eq!(compact["runtime"]["security_policy_path"], "policy.json");
    assert!(compact["runtime"].get("base_policy").is_none());
    assert!(compact["runtime"].get("artifact_dir").is_none());
    let encoded = serde_json::to_string(&compact).expect("json");
    assert!(!encoded.contains("/tmp/secret-dir"));
}

#[test]
fn compact_capture_omits_artifact_path_and_pixels() {
    let response = HostResponse::ArtifactCaptured {
        artifact: ObservationArtifact {
            id: Uuid::nil(),
            path: "/tmp/secret.png".to_string(),
            sha256: "abc".to_string(),
            mime_type: "image/png".to_string(),
            bytes: 12,
            created_at: chrono::Utc::now(),
            unchanged: false,
        },
    };
    let compact = compact_host_response(&response);
    let encoded = serde_json::to_string(&compact).expect("json");
    assert!(!encoded.contains("/tmp/secret.png"));
    assert!(!encoded.contains("fake-image"));
    assert_eq!(compact["bytes"], 12);
}

#[test]
fn compact_app_list_truncates_titles() {
    let long_name = "N".repeat(200);
    let response = HostResponse::AppList {
        apps: vec![AppDescriptor {
            name: long_name,
            pid: Some(1),
        }],
        truncated: false,
    };
    let compact = compact_host_response(&response);
    let name = compact["apps"][0]["name"].as_str().expect("name");
    assert!(name.chars().count() <= 81);
}
