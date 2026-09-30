use p256::ecdsa::SigningKey;

use crate::enrollment::{
    EnrollmentChallenge, create_enrollment_proof, decode_enrollment_challenge,
    decode_enrollment_proof, derive_pairing_code, encode_enrollment_challenge,
    encode_enrollment_proof, verify_enrollment_proof,
};
use crate::types::{DeviceId, Nonce, SessionId};

fn test_signing_key_one() -> SigningKey {
    SigningKey::from_slice(&[0x01; 32]).expect("fixed test key must be valid")
}

fn test_signing_key_two() -> SigningKey {
    SigningKey::from_slice(&[0x02; 32]).expect("fixed test key must be valid")
}

fn challenge() -> EnrollmentChallenge {
    EnrollmentChallenge {
        windows_device_id: DeviceId([0x11; 16]),

        enrollment_id: SessionId([0x22; 16]),

        nonce: Nonce([0x33; 32]),

        issued_at_ms: 1_000_000,

        expires_at_ms: 1_045_000,
    }
}

#[test]
fn enrollment_challenge_round_trips() {
    let original = challenge();

    let encoded = encode_enrollment_challenge(&original).unwrap();

    let decoded = decode_enrollment_challenge(&encoded).unwrap();

    assert_eq!(original, decoded);
}

#[test]
fn enrollment_proof_round_trips() {
    let signing_key = test_signing_key_one();

    let proof = create_enrollment_proof(&signing_key, DeviceId([0xaa; 16]), &challenge()).unwrap();

    let encoded = encode_enrollment_proof(&proof).unwrap();

    let decoded = decode_enrollment_proof(&encoded).unwrap();

    assert_eq!(proof, decoded);
}

#[test]
fn valid_enrollment_proof_verifies() {
    let signing_key = test_signing_key_one();

    let challenge = challenge();

    let proof = create_enrollment_proof(&signing_key, DeviceId([0xaa; 16]), &challenge).unwrap();

    verify_enrollment_proof(&proof, &challenge).unwrap();
}

#[test]
fn changed_enrollment_id_is_rejected() {
    let signing_key = test_signing_key_one();

    let challenge = challenge();

    let mut proof =
        create_enrollment_proof(&signing_key, DeviceId([0xaa; 16]), &challenge).unwrap();

    proof.enrollment_id = SessionId([0x99; 16]);

    assert!(verify_enrollment_proof(&proof, &challenge).is_err());
}

#[test]
fn changed_device_id_breaks_signature() {
    let signing_key = test_signing_key_one();

    let challenge = challenge();

    let mut proof =
        create_enrollment_proof(&signing_key, DeviceId([0xaa; 16]), &challenge).unwrap();

    proof.android_device_id = DeviceId([0xbb; 16]);

    assert!(verify_enrollment_proof(&proof, &challenge).is_err());
}

#[test]
fn changed_public_key_is_rejected() {
    let signing_key = test_signing_key_one();

    let other_key = test_signing_key_two();

    let challenge = challenge();

    let mut proof =
        create_enrollment_proof(&signing_key, DeviceId([0xaa; 16]), &challenge).unwrap();

    let point = other_key.verifying_key().to_sec1_point(false);

    proof.public_key_sec1.copy_from_slice(point.as_ref());

    assert!(verify_enrollment_proof(&proof, &challenge).is_err());
}

#[test]
fn changed_nonce_breaks_enrollment_proof() {
    let signing_key = test_signing_key_one();

    let original_challenge = challenge();

    let proof =
        create_enrollment_proof(&signing_key, DeviceId([0xaa; 16]), &original_challenge).unwrap();

    let mut changed_challenge = original_challenge;

    changed_challenge.nonce = Nonce([0x44; 32]);

    assert!(verify_enrollment_proof(&proof, &changed_challenge).is_err());
}

#[test]
fn changed_windows_device_breaks_enrollment_proof() {
    let signing_key = test_signing_key_one();

    let original_challenge = challenge();

    let proof =
        create_enrollment_proof(&signing_key, DeviceId([0xaa; 16]), &original_challenge).unwrap();

    let mut changed_challenge = original_challenge;

    changed_challenge.windows_device_id = DeviceId([0x77; 16]);

    assert!(verify_enrollment_proof(&proof, &changed_challenge).is_err());
}

#[test]
fn pairing_code_is_deterministic() {
    let signing_key = test_signing_key_one();

    let challenge = challenge();

    let proof = create_enrollment_proof(&signing_key, DeviceId([0xaa; 16]), &challenge).unwrap();

    let first = derive_pairing_code(&challenge, &proof).unwrap();

    let second = derive_pairing_code(&challenge, &proof).unwrap();

    assert_eq!(first, second);

    assert!(first <= 999_999);
}

#[test]
fn different_phone_changes_pairing_code() {
    let signing_key_one = test_signing_key_one();

    let signing_key_two = test_signing_key_two();

    let challenge = challenge();

    let first =
        create_enrollment_proof(&signing_key_one, DeviceId([0xaa; 16]), &challenge).unwrap();

    let second =
        create_enrollment_proof(&signing_key_two, DeviceId([0xbb; 16]), &challenge).unwrap();

    let first_code = derive_pairing_code(&challenge, &first).unwrap();

    let second_code = derive_pairing_code(&challenge, &second).unwrap();

    assert_ne!(first_code, second_code);
}
