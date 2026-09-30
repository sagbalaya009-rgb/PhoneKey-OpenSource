use crate::types::{DEVICE_ID_LEN, DeviceId, NONCE_LEN, Nonce, SESSION_ID_LEN, SessionId};

#[test]
fn device_id_has_fixed_length() {
    let id = DeviceId([0x11; DEVICE_ID_LEN]);
    assert_eq!(id.0.len(), 16);
}

#[test]
fn session_id_has_fixed_length() {
    let id = SessionId([0x22; SESSION_ID_LEN]);
    assert_eq!(id.0.len(), 16);
}

#[test]
fn nonce_has_fixed_length() {
    let nonce = Nonce([0x33; NONCE_LEN]);
    assert_eq!(nonce.0.len(), 32);
}

#[test]
fn identifiers_compare_by_value() {
    assert_eq!(DeviceId([1; DEVICE_ID_LEN]), DeviceId([1; DEVICE_ID_LEN]));

    assert_ne!(DeviceId([1; DEVICE_ID_LEN]), DeviceId([2; DEVICE_ID_LEN]));
}
