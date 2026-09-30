use std::time::Instant;

use p256::SecretKey;
use p256::ecdsa::SigningKey;
use phonekey_file_vault::{key_return, key_wrap, package, recovery};
use phonekey_protocol::file_open::{
    FileOpenChallenge, FileOpenProof, FileOpenSession, sign_file_open,
};
use phonekey_protocol::types::{DeviceId, Nonce, SessionId};
use sha2::{Digest, Sha256};

#[test]
fn dummy_file_opens_only_after_bound_phone_proof() {
    let phone_agreement = SecretKey::from_slice(&[7; 32]).unwrap();
    let phone_signing = SigningKey::from_bytes((&[8; 32]).into()).unwrap();
    let laptop_return = SecretKey::from_slice(&[9; 32]).unwrap();
    let recovery_key = recovery::new_recovery_key().unwrap();
    let package = package::seal_package(
        b"dummy document",
        &phone_agreement.public_key().to_sec1_bytes(),
        &recovery_key,
    )
    .unwrap();
    let parsed = package::parse(&package).unwrap();
    let return_public = laptop_return.public_key().to_sec1_bytes();
    let challenge = FileOpenChallenge {
        windows_device_id: DeviceId([1; 16]),
        phone_device_id: DeviceId([2; 16]),
        session_id: SessionId([3; 16]),
        nonce: Nonce([4; 32]),
        envelope_sha256: parsed.envelope_sha256,
        phone_wrap: parsed.phone_wrap.try_into().unwrap(),
        return_public_sec1: return_public.as_ref().try_into().unwrap(),
        issued_at_ms: 1_000,
        expires_at_ms: 61_000,
    };
    let qr = challenge.qr_payload().unwrap();
    assert!(qr.starts_with("PKF3|"));
    let started = Instant::now();
    let mut session = FileOpenSession::new(
        challenge.clone(),
        phone_signing
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        started,
    )
    .unwrap();
    let file_key = key_wrap::unwrap_with_phone_secret(
        &challenge.phone_wrap,
        &challenge.envelope_sha256,
        &phone_agreement,
    )
    .unwrap();
    let challenge_hash: [u8; 32] = Sha256::digest(challenge.transcript().unwrap()).into();
    let returned =
        key_return::seal_for_laptop(&file_key, &challenge_hash, &challenge.return_public_sec1)
            .unwrap();
    let proof = FileOpenProof {
        phone_device_id: challenge.phone_device_id,
        session_id: challenge.session_id,
        signature: sign_file_open(&phone_signing, &challenge, &returned).unwrap(),
        encrypted_file_key: returned,
    };
    let mut changed = proof.clone();
    changed.encrypted_file_key[100] ^= 1;
    assert!(
        session
            .redeem(&changed, &parsed.envelope_sha256, 2_000, started)
            .is_err()
    );
    session
        .redeem(&proof, &parsed.envelope_sha256, 2_000, started)
        .unwrap();
    assert!(
        session
            .redeem(&proof, &parsed.envelope_sha256, 2_001, started)
            .is_err()
    );
    let received =
        key_return::open_on_laptop(&proof.encrypted_file_key, &challenge_hash, &laptop_return)
            .unwrap();
    assert_eq!(
        phonekey_file_vault::open(parsed.envelope, &received)
            .unwrap()
            .as_slice(),
        b"dummy document"
    );
}
