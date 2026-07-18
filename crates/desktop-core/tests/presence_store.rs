use desktop_core::{PresencePhase, PresenceSnapshot, PresenceStore};
use std::fs;
use tempfile::tempdir;

#[test]
fn presence_store_writes_current_and_events() {
    let dir = tempdir().expect("tempdir");
    let store = PresenceStore::new(dir.path()).expect("store");

    let mut snap = PresenceSnapshot::idle("test");
    snap.phase = PresencePhase::Controlling;
    snap.capability = Some("input.click".to_string());
    snap.detail = Some("click (10, 20)".to_string());
    snap.dry_run = true;

    store.publish(&snap).expect("publish");

    let current = fs::read_to_string(store.state_path()).expect("read current");
    assert!(current.contains("controlling"));
    assert!(current.contains("input.click"));

    let events = fs::read_to_string(store.events_path()).expect("read events");
    assert!(events.contains("state_changed"));
    assert!(events.lines().count() >= 1);
}

#[test]
fn presence_store_stop_and_pause_control_files() {
    let dir = tempdir().expect("tempdir");
    let store = PresenceStore::new(dir.path()).expect("store");

    assert!(!store.is_stop_requested());
    assert!(!store.is_pause_requested());

    store.request_pause("human").expect("pause");
    assert!(store.is_pause_requested());
    assert!(!store.is_stop_requested());

    store.request_stop("operator").expect("stop");
    assert!(store.is_stop_requested());
    // stop clears pause
    assert!(!store.is_pause_requested());

    store.clear_stop().expect("clear stop");
    assert!(!store.is_stop_requested());
}
