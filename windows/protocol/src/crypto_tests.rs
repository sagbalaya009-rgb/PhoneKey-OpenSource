use p256::ecdsa::SigningKey;

use crate::crypto::{
    P256_PUBLIC_KEY_LEN, P256_SIGNATURE_LEN, public_key_sec1, sign_login_challenge,
    verify_login_challenge,
};
use crate::error::ProtocolError;
use crate::messages::{LoginChallenge, LoginOperation};
use crate::types::{DEVICE_ID_LEN, DeviceId, NONCE_LEN, Nonce, SESSION_ID_LEN, SessionId};

fn signing_key() -> SigningKey {
    let private_key = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    SigningKey::from_slice(&private_key).unwrap()
}

fn challenge() -> LoginChallenge {
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
fn public_key_is_uncompressed_sec1_length() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    assert_eq!(public_key.len(), P256_PUBLIC_KEY_LEN);
    assert_eq!(public_key[0], 0x04);
}

#[test]
fn signature_has_fixed_length() {
    let key = signing_key();

    let signature = sign_login_challenge(&key, &challenge()).unwrap();

    assert_eq!(signature.len(), P256_SIGNATURE_LEN);
}

#[test]
fn valid_signature_verifies() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let message = challenge();
    let signature = sign_login_challenge(&key, &message).unwrap();

    assert_eq!(
        verify_login_challenge(&public_key, &message, &signature),
        Ok(())
    );
}

#[test]
fn changed_nonce_breaks_signature() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let original = challenge();
    let signature = sign_login_challenge(&key, &original).unwrap();

    let mut changed = original;
    changed.nonce = Nonce([0x99; NONCE_LEN]);

    assert_eq!(
        verify_login_challenge(&public_key, &changed, &signature),
        Err(ProtocolError::InvalidSignature)
    );
}

#[test]
fn changed_session_breaks_signature() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let original = challenge();
    let signature = sign_login_challenge(&key, &original).unwrap();

    let mut changed = original;
    changed.session_id = SessionId([0xaa; SESSION_ID_LEN]);

    assert_eq!(
        verify_login_challenge(&public_key, &changed, &signature),
        Err(ProtocolError::InvalidSignature)
    );
}

#[test]
fn changed_account_breaks_signature() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let original = challenge();
    let signature = sign_login_challenge(&key, &original).unwrap();

    let mut changed = original;
    changed.account_binding = vec![0x55; 32];

    assert_eq!(
        verify_login_challenge(&public_key, &changed, &signature),
        Err(ProtocolError::InvalidSignature)
    );
}

#[test]
fn wrong_public_key_is_rejected() {
    let first_key = signing_key();

    let second_private_key = [0x42; 32];
    let second_key = SigningKey::from_slice(&second_private_key).unwrap();

    let message = challenge();
    let signature = sign_login_challenge(&first_key, &message).unwrap();

    let wrong_public_key = public_key_sec1(&second_key);

    assert_eq!(
        verify_login_challenge(&wrong_public_key, &message, &signature),
        Err(ProtocolError::InvalidSignature)
    );
}

#[test]
fn malformed_public_key_is_rejected() {
    let key = signing_key();
    let signature = sign_login_challenge(&key, &challenge()).unwrap();

    assert_eq!(
        verify_login_challenge(&[0x01, 0x02, 0x03], &challenge(), &signature),
        Err(ProtocolError::InvalidCryptoKey)
    );
}

#[test]
fn malformed_signature_length_is_rejected() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    assert_eq!(
        verify_login_challenge(&public_key, &challenge(), &[0u8; 63]),
        Err(ProtocolError::InvalidSignature)
    );
}
