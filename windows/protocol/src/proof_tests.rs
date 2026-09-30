use p256::ecdsa::SigningKey;

use crate::crypto::public_key_sec1;
use crate::error::ProtocolError;
use crate::messages::{LoginChallenge, LoginOperation};
use crate::proof::{
    create_login_proof, decode_login_proof, encode_login_proof, verify_login_proof,
};
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

fn android_device_id() -> DeviceId {
    DeviceId([0xaa; DEVICE_ID_LEN])
}

#[test]
fn proof_round_trips() {
    let key = signing_key();

    let proof = create_login_proof(&key, android_device_id(), &challenge()).unwrap();

    let encoded = encode_login_proof(&proof).unwrap();
    let decoded = decode_login_proof(&encoded).unwrap();

    assert_eq!(decoded, proof);
}

#[test]
fn valid_proof_verifies() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    assert_eq!(
        verify_login_proof(&proof, &android_device_id(), &public_key, &challenge),
        Ok(())
    );
}

#[test]
fn wrong_android_device_is_rejected() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    let wrong_device = DeviceId([0xbb; DEVICE_ID_LEN]);

    assert_eq!(
        verify_login_proof(&proof, &wrong_device, &public_key, &challenge),
        Err(ProtocolError::ProofBindingMismatch)
    );
}

#[test]
fn wrong_session_is_rejected() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();

    let mut proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    proof.session_id = SessionId([0xcc; SESSION_ID_LEN]);

    assert_eq!(
        verify_login_proof(&proof, &android_device_id(), &public_key, &challenge),
        Err(ProtocolError::ProofBindingMismatch)
    );
}

#[test]
fn changed_challenge_breaks_proof() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let original = challenge();

    let proof = create_login_proof(&key, android_device_id(), &original).unwrap();

    let mut changed = original;
    changed.nonce = Nonce([0x99; NONCE_LEN]);

    assert_eq!(
        verify_login_proof(&proof, &android_device_id(), &public_key, &changed),
        Err(ProtocolError::InvalidSignature)
    );
}

#[test]
fn wrong_public_key_breaks_proof() {
    let key = signing_key();

    let second_key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let wrong_public_key = public_key_sec1(&second_key);

    let challenge = challenge();

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    assert_eq!(
        verify_login_proof(&proof, &android_device_id(), &wrong_public_key, &challenge),
        Err(ProtocolError::InvalidSignature)
    );
}
