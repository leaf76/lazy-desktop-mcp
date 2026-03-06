use desktop_core::{AuditEvent, AuditPayload, AuditPayloadKind, Capability, hash_bytes};
use uuid::Uuid;

#[test]
fn hashes_sensitive_input_without_storing_plaintext() {
    let payload = AuditPayload::from_sensitive_bytes(b"super-secret");
    let event = AuditEvent::new(
        "trace-1",
        Capability::InputType,
        "allowed",
        Some(Uuid::new_v4()),
        payload.clone(),
    );

    assert_eq!(payload.kind, AuditPayloadKind::SensitiveHash);
    assert_eq!(payload.preview, None);
    assert_eq!(payload.sha256, Some(hash_bytes(b"super-secret")));
    assert_eq!(event.payload.sha256, payload.sha256);
}
