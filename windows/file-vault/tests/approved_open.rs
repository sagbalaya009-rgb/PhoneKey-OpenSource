use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use p256::SecretKey;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use phonekey_file_vault::{
    approved_open::FileOpenAttempt, files, key_return, key_wrap, package, phone_binding, recovery,
};
use phonekey_protocol::file_open::{FileOpenProof, sign_file_open};
use phonekey_protocol::types::DeviceId;
use sha2::{Digest, Sha256};

fn approved_proof(
    attempt: &FileOpenAttempt,
    phone_agreement: &SecretKey,
    phone_signing: &SigningKey,
) -> FileOpenProof {
    let challenge = attempt.challenge();
    let file_key = key_wrap::unwrap_with_phone_secret(
        &challenge.phone_wrap,
        &challenge.envelope_sha256,
        phone_agreement,
    )
    .unwrap();
    let challenge_hash: [u8; 32] = Sha256::digest(challenge.transcript().unwrap()).into();
    let encrypted_file_key =
        key_return::seal_for_laptop(&file_key, &challenge_hash, &challenge.return_public_sec1)
            .unwrap();
    FileOpenProof {
        phone_device_id: challenge.phone_device_id,
        session_id: challenge.session_id,
        signature: sign_file_open(phone_signing, challenge, &encrypted_file_key).unwrap(),
        encrypted_file_key,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 15) as usize] as char);
    }
    value
}

#[test]
fn signed_phone_binding_encrypts_then_fresh_phone_proof_opens() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("dummy.txt");
    let encrypted = dir.path().join("dummy.pkp");
    fs::write(&source, b"dummy file only").unwrap();
    let phone_id = DeviceId([2; 16]);
    let phone_agreement = SecretKey::from_slice(&[7; 32]).unwrap();
    let phone_signing = SigningKey::from_bytes((&[8; 32]).into()).unwrap();
    let agreement_public: [u8; 65] = phone_agreement
        .public_key()
        .to_sec1_bytes()
        .as_ref()
        .try_into()
        .unwrap();
    let signature: Signature = phone_signing.sign(&phone_binding::binding_transcript(
        &phone_id,
        &agreement_public,
    ));
    let signature = signature.normalize_s();
    let binding = format!(
        "PKB1|{}|{}|{}",
        lower_hex(&phone_id.0),
        lower_hex(&agreement_public),
        lower_hex(signature.to_bytes().as_ref())
    );
    let recovery_key = recovery::new_recovery_key().unwrap();
    let trusted_key = phone_signing.verifying_key().to_sec1_point(false);
    files::encrypt_with_signed_phone_binding(
        &source,
        &encrypted,
        &binding,
        phone_id,
        trusted_key.as_bytes(),
        &recovery_key,
    )
    .unwrap();
    assert_eq!(fs::read(&source).unwrap(), b"dummy file only");
    let started = Instant::now();
    let mut attempt = FileOpenAttempt::begin(
        &encrypted,
        DeviceId([1; 16]),
        phone_id,
        trusted_key.as_bytes(),
        100_000,
        started,
    )
    .unwrap();
    let proof = approved_proof(&attempt, &phone_agreement, &phone_signing);
    assert_eq!(
        attempt
            .complete(&proof, 100_100, started + Duration::from_millis(100))
            .unwrap()
            .as_slice(),
        b"dummy file only"
    );
    let bad_destination = dir.path().join("bad.pkp");
    assert!(
        files::encrypt_with_signed_phone_binding(
            &source,
            &bad_destination,
            &binding,
            DeviceId([3; 16]),
            trusted_key.as_bytes(),
            &recovery_key,
        )
        .is_err()
    );
    assert!(!bad_destination.exists());
}

#[test]
fn only_fresh_bound_phone_proof_opens_once() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("test.pkp");
    let phone_agreement = SecretKey::from_slice(&[7; 32]).unwrap();
    let phone_signing = SigningKey::from_bytes((&[8; 32]).into()).unwrap();
    let recovery = recovery::new_recovery_key().unwrap();
    fs::write(
        &source,
        package::seal_package(
            b"dummy file only",
            &phone_agreement.public_key().to_sec1_bytes(),
            &recovery,
        )
        .unwrap(),
    )
    .unwrap();

    let started = Instant::now();
    let mut attempt = FileOpenAttempt::begin(
        &source,
        DeviceId([1; 16]),
        DeviceId([2; 16]),
        phone_signing
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes(),
        100_000,
        started,
    )
    .unwrap();
    assert!(attempt.qr_payload().unwrap().starts_with("PKF3|"));
    let proof = approved_proof(&attempt, &phone_agreement, &phone_signing);
    let mut altered = proof.clone();
    altered.encrypted_file_key[100] ^= 1;
    assert!(
        attempt
            .complete(&altered, 100_100, started + Duration::from_millis(100))
            .is_err()
    );
    assert_eq!(
        attempt
            .complete(&proof, 100_200, started + Duration::from_millis(200))
            .unwrap()
            .as_slice(),
        b"dummy file only"
    );
    assert!(
        attempt
            .complete(&proof, 100_300, started + Duration::from_millis(300))
            .is_err()
    );
}

#[test]
fn changed_package_and_expired_approval_never_release_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("test.pkp");
    let phone_agreement = SecretKey::from_slice(&[7; 32]).unwrap();
    let phone_signing = SigningKey::from_bytes((&[8; 32]).into()).unwrap();
    let recovery = recovery::new_recovery_key().unwrap();
    let original = package::seal_package(
        b"dummy file only",
        &phone_agreement.public_key().to_sec1_bytes(),
        &recovery,
    )
    .unwrap();
    fs::write(&source, &original).unwrap();
    let started = Instant::now();
    let mut attempt = FileOpenAttempt::begin(
        &source,
        DeviceId([1; 16]),
        DeviceId([2; 16]),
        phone_signing
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes(),
        100_000,
        started,
    )
    .unwrap();
    let proof = approved_proof(&attempt, &phone_agreement, &phone_signing);
    let mut changed = original.clone();
    changed[80] ^= 1; // Change the phone wrap, leaving the envelope unchanged.
    fs::write(&source, changed).unwrap();
    assert!(
        attempt
            .complete(&proof, 100_100, started + Duration::from_millis(100))
            .is_err()
    );
    fs::write(&source, original).unwrap();
    assert!(
        attempt
            .complete(&proof, 160_000, started + Duration::from_secs(60))
            .is_err()
    );
}

#[test]
fn another_phone_signature_cannot_open_file() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("test.pkp");
    let phone_agreement = SecretKey::from_slice(&[7; 32]).unwrap();
    let trusted_signing = SigningKey::from_bytes((&[8; 32]).into()).unwrap();
    let impostor_signing = SigningKey::from_bytes((&[9; 32]).into()).unwrap();
    let recovery = recovery::new_recovery_key().unwrap();
    fs::write(
        &source,
        package::seal_package(
            b"dummy file only",
            &phone_agreement.public_key().to_sec1_bytes(),
            &recovery,
        )
        .unwrap(),
    )
    .unwrap();
    let started = Instant::now();
    let mut attempt = FileOpenAttempt::begin(
        &source,
        DeviceId([1; 16]),
        DeviceId([2; 16]),
        trusted_signing
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes(),
        100_000,
        started,
    )
    .unwrap();
    let proof = approved_proof(&attempt, &phone_agreement, &impostor_signing);
    assert!(
        attempt
            .complete(&proof, 100_100, started + Duration::from_millis(100))
            .is_err()
    );
}

#[test]
fn streamed_file_above_old_limit_exports_only_after_phone_proof() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("large.bin");
    let encrypted = dir.path().join("large.pkp");
    let exported = dir.path().join("approved.bin");
    let recovered = dir.path().join("recovered.bin");
    let mut original = vec![0u8; 20 * 1024 * 1024 + 7];
    for (index, byte) in original.iter_mut().enumerate() {
        *byte = (index % 239) as u8;
    }
    fs::write(&source, &original).unwrap();
    let phone_agreement = SecretKey::from_slice(&[7; 32]).unwrap();
    let phone_signing = SigningKey::from_bytes((&[8; 32]).into()).unwrap();
    let recovery_key = recovery::new_recovery_key().unwrap();
    files::encrypt_package_to_new_file(
        &source,
        &encrypted,
        &phone_agreement.public_key().to_sec1_bytes(),
        &recovery_key,
    )
    .unwrap();
    let started = Instant::now();
    let mut attempt = FileOpenAttempt::begin(
        &encrypted,
        DeviceId([1; 16]),
        DeviceId([2; 16]),
        phone_signing
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes(),
        100_000,
        started,
    )
    .unwrap();
    assert!(!exported.exists());
    let proof = approved_proof(&attempt, &phone_agreement, &phone_signing);
    let (metadata, key) = attempt
        .complete_key(&proof, 100_100, started + Duration::from_millis(100))
        .unwrap();
    files::export_package_to_new_file(&encrypted, &exported, &metadata, &key).unwrap();
    assert_eq!(fs::read(&exported).unwrap(), original);
    assert!(files::export_package_to_new_file(&encrypted, &exported, &metadata, &key).is_err());
    let wrong = recovery::new_recovery_key().unwrap();
    assert!(files::recover_package_to_new_file(&encrypted, &recovered, &wrong).is_err());
    assert!(!recovered.exists());
    files::recover_package_to_new_file(&encrypted, &recovered, &recovery_key).unwrap();
    assert_eq!(fs::read(&recovered).unwrap(), original);
    let altered = dir.path().join("altered.pkp");
    let refused = dir.path().join("refused.bin");
    fs::copy(&encrypted, &altered).unwrap();
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&altered)
        .unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&[byte[0] ^ 1]).unwrap();
    drop(file);
    assert!(files::export_package_to_new_file(&altered, &refused, &metadata, &key).is_err());
    assert!(!refused.exists());
}
