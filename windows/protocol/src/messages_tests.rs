use crate::cbor::{CborValue, decode, encode};
use crate::error::ProtocolError;
use crate::messages::{
    LoginChallenge, LoginOperation, decode_login_challenge, encode_login_challenge,
};
use crate::types::{DEVICE_ID_LEN, DeviceId, NONCE_LEN, Nonce, SESSION_ID_LEN, SessionId};

fn sample_challenge() -> LoginChallenge {
    LoginChallenge {
        windows_device_id: DeviceId([0x11; DEVICE_ID_LEN]),
        session_id: SessionId([0x22; SESSION_ID_LEN]),
        nonce: Nonce([0x33; NONCE_LEN]),
        issued_at_ms: 1_000_000,
        expires_at_ms: 1_060_000,
        operation: LoginOperation::Logon,
        account_binding: vec![0x44; 32],
    }
}

#[test]
fn login_challenge_round_trips() {
    let original = sample_challenge();

    let encoded = encode_login_challenge(&original).unwrap();
    let decoded = decode_login_challenge(&encoded).unwrap();

    assert_eq!(decoded, original);
}

#[test]
fn unlock_operation_round_trips() {
    let mut challenge = sample_challenge();
    challenge.operation = LoginOperation::Unlock;

    let encoded = encode_login_challenge(&challenge).unwrap();
    let decoded = decode_login_challenge(&encoded).unwrap();

    assert_eq!(decoded.operation, LoginOperation::Unlock);
}

#[test]
fn invalid_expiry_is_rejected() {
    let mut challenge = sample_challenge();
    challenge.expires_at_ms = challenge.issued_at_ms;

    assert_eq!(
        encode_login_challenge(&challenge),
        Err(ProtocolError::InvalidFieldValue(7))
    );
}

#[test]
fn empty_account_binding_is_rejected() {
    let mut challenge = sample_challenge();
    challenge.account_binding.clear();

    assert_eq!(
        encode_login_challenge(&challenge),
        Err(ProtocolError::InvalidFieldLength(9))
    );
}

#[test]
fn wrong_protocol_version_is_rejected() {
    let encoded = encode_login_challenge(&sample_challenge()).unwrap();
    let mut value = decode(&encoded).unwrap();

    if let CborValue::Map(ref mut map) = value {
        map.insert(1, CborValue::Unsigned(999));
    }

    let mutated = encode(&value).unwrap();

    assert_eq!(
        decode_login_challenge(&mutated),
        Err(ProtocolError::InvalidFieldValue(1))
    );
}

#[test]
fn wrong_message_type_is_rejected() {
    let encoded = encode_login_challenge(&sample_challenge()).unwrap();
    let mut value = decode(&encoded).unwrap();

    if let CborValue::Map(ref mut map) = value {
        map.insert(2, CborValue::Unsigned(999));
    }

    let mutated = encode(&value).unwrap();

    assert_eq!(
        decode_login_challenge(&mutated),
        Err(ProtocolError::InvalidFieldValue(2))
    );
}

#[test]
fn unexpected_field_is_rejected() {
    let encoded = encode_login_challenge(&sample_challenge()).unwrap();
    let mut value = decode(&encoded).unwrap();

    if let CborValue::Map(ref mut map) = value {
        map.insert(99, CborValue::Unsigned(1));
    }

    let mutated = encode(&value).unwrap();

    assert_eq!(
        decode_login_challenge(&mutated),
        Err(ProtocolError::UnexpectedField(99))
    );
}

#[test]
fn invalid_device_id_length_is_rejected() {
    let encoded = encode_login_challenge(&sample_challenge()).unwrap();
    let mut value = decode(&encoded).unwrap();

    if let CborValue::Map(ref mut map) = value {
        map.insert(3, CborValue::Bytes(vec![0; 15]));
    }

    let mutated = encode(&value).unwrap();

    assert_eq!(
        decode_login_challenge(&mutated),
        Err(ProtocolError::InvalidFieldLength(3))
    );
}

#[test]
fn invalid_operation_is_rejected() {
    let encoded = encode_login_challenge(&sample_challenge()).unwrap();
    let mut value = decode(&encoded).unwrap();

    if let CborValue::Map(ref mut map) = value {
        map.insert(8, CborValue::Unsigned(99));
    }

    let mutated = encode(&value).unwrap();

    assert_eq!(
        decode_login_challenge(&mutated),
        Err(ProtocolError::InvalidFieldValue(8))
    );
}
