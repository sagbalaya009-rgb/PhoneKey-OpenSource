use p256::ecdsa::SigningKey;

use crate::crypto::public_key_sec1;
use crate::error::ProtocolError;
use crate::messages::{LoginChallenge, LoginOperation};
use crate::proof::create_login_proof;
use crate::session::SessionStore;
use crate::types::{
    DEVICE_ID_LEN, DeviceId, MAX_LOGIN_SESSION_TTL_MS, NONCE_LEN, Nonce, SESSION_ID_LEN, SessionId,
};

fn signing_key() -> SigningKey {
    let private_key = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    SigningKey::from_slice(&private_key).unwrap()
}

fn windows_device_id() -> DeviceId {
    DeviceId([0x11; DEVICE_ID_LEN])
}

fn android_device_id() -> DeviceId {
    DeviceId([0xaa; DEVICE_ID_LEN])
}

fn account_binding() -> Vec<u8> {
    vec![0x44; 32]
}

fn challenge() -> LoginChallenge {
    LoginChallenge {
        windows_device_id: windows_device_id(),
        session_id: SessionId([0x22; SESSION_ID_LEN]),
        nonce: Nonce([0x33; NONCE_LEN]),
        issued_at_ms: 1_000_000,
        expires_at_ms: 1_000_000 + MAX_LOGIN_SESSION_TTL_MS,
        operation: LoginOperation::Logon,
        account_binding: account_binding(),
    }
}

#[test]
fn valid_session_is_consumed_once() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();
    let session_id = challenge.session_id;

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    let mut store = SessionStore::new();
    store.register(challenge).unwrap();

    assert_eq!(
        store.verify_and_consume(
            session_id,
            &proof,
            &android_device_id(),
            &public_key,
            &windows_device_id(),
            &account_binding(),
            LoginOperation::Logon,
            1_030_000,
        ),
        Ok(())
    );

    assert_eq!(store.active_count(), 0);
    assert!(store.is_consumed(&session_id));
}

#[test]
fn replay_is_rejected() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();
    let session_id = challenge.session_id;

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    let mut store = SessionStore::new();
    store.register(challenge).unwrap();

    store
        .verify_and_consume(
            session_id,
            &proof,
            &android_device_id(),
            &public_key,
            &windows_device_id(),
            &account_binding(),
            LoginOperation::Logon,
            1_030_000,
        )
        .unwrap();

    assert_eq!(
        store.verify_and_consume(
            session_id,
            &proof,
            &android_device_id(),
            &public_key,
            &windows_device_id(),
            &account_binding(),
            LoginOperation::Logon,
            1_030_001,
        ),
        Err(ProtocolError::SessionAlreadyConsumed)
    );
}

#[test]
fn invalid_signature_does_not_consume_session() {
    let key = signing_key();

    let wrong_key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let wrong_public_key = public_key_sec1(&wrong_key);

    let challenge = challenge();
    let session_id = challenge.session_id;

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    let mut store = SessionStore::new();
    store.register(challenge).unwrap();

    assert_eq!(
        store.verify_and_consume(
            session_id,
            &proof,
            &android_device_id(),
            &wrong_public_key,
            &windows_device_id(),
            &account_binding(),
            LoginOperation::Logon,
            1_030_000,
        ),
        Err(ProtocolError::InvalidSignature)
    );

    assert_eq!(store.active_count(), 1);
    assert!(!store.is_consumed(&session_id));
}

#[test]
fn expired_session_is_rejected() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();
    let session_id = challenge.session_id;

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    let expires_at = challenge.expires_at_ms;

    let mut store = SessionStore::new();
    store.register(challenge).unwrap();

    assert_eq!(
        store.verify_and_consume(
            session_id,
            &proof,
            &android_device_id(),
            &public_key,
            &windows_device_id(),
            &account_binding(),
            LoginOperation::Logon,
            expires_at,
        ),
        Err(ProtocolError::SessionExpired)
    );
}

#[test]
fn session_before_issue_time_is_rejected() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();
    let session_id = challenge.session_id;

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    let mut store = SessionStore::new();
    store.register(challenge).unwrap();

    assert_eq!(
        store.verify_and_consume(
            session_id,
            &proof,
            &android_device_id(),
            &public_key,
            &windows_device_id(),
            &account_binding(),
            LoginOperation::Logon,
            999_999,
        ),
        Err(ProtocolError::SessionNotYetValid)
    );
}

#[test]
fn issue_time_boundary_is_valid() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();
    let session_id = challenge.session_id;
    let issued_at = challenge.issued_at_ms;

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    let mut store = SessionStore::new();
    store.register(challenge).unwrap();

    assert_eq!(
        store.verify_and_consume(
            session_id,
            &proof,
            &android_device_id(),
            &public_key,
            &windows_device_id(),
            &account_binding(),
            LoginOperation::Logon,
            issued_at,
        ),
        Ok(())
    );
}

#[test]
fn overlong_session_lifetime_is_rejected() {
    let mut challenge = challenge();

    challenge.expires_at_ms = challenge.issued_at_ms + MAX_LOGIN_SESSION_TTL_MS + 1;

    let mut store = SessionStore::new();

    assert_eq!(
        store.register(challenge),
        Err(ProtocolError::SessionLifetimeTooLong)
    );
}

#[test]
fn wrong_windows_device_is_rejected() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();
    let session_id = challenge.session_id;

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    let wrong_windows_device = DeviceId([0xbb; DEVICE_ID_LEN]);

    let mut store = SessionStore::new();
    store.register(challenge).unwrap();

    assert_eq!(
        store.verify_and_consume(
            session_id,
            &proof,
            &android_device_id(),
            &public_key,
            &wrong_windows_device,
            &account_binding(),
            LoginOperation::Logon,
            1_030_000,
        ),
        Err(ProtocolError::SessionBindingMismatch)
    );
}

#[test]
fn wrong_account_binding_is_rejected() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();
    let session_id = challenge.session_id;

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    let wrong_account = vec![0x99; 32];

    let mut store = SessionStore::new();
    store.register(challenge).unwrap();

    assert_eq!(
        store.verify_and_consume(
            session_id,
            &proof,
            &android_device_id(),
            &public_key,
            &windows_device_id(),
            &wrong_account,
            LoginOperation::Logon,
            1_030_000,
        ),
        Err(ProtocolError::SessionBindingMismatch)
    );
}

#[test]
fn wrong_operation_is_rejected() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();
    let session_id = challenge.session_id;

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    let mut store = SessionStore::new();
    store.register(challenge).unwrap();

    assert_eq!(
        store.verify_and_consume(
            session_id,
            &proof,
            &android_device_id(),
            &public_key,
            &windows_device_id(),
            &account_binding(),
            LoginOperation::Unlock,
            1_030_000,
        ),
        Err(ProtocolError::SessionBindingMismatch)
    );
}

#[test]
fn unknown_session_is_rejected() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    let challenge = challenge();

    let proof = create_login_proof(&key, android_device_id(), &challenge).unwrap();

    let mut store = SessionStore::new();

    assert_eq!(
        store.verify_and_consume(
            challenge.session_id,
            &proof,
            &android_device_id(),
            &public_key,
            &windows_device_id(),
            &account_binding(),
            LoginOperation::Logon,
            1_030_000,
        ),
        Err(ProtocolError::UnknownSession)
    );
}

#[test]
fn duplicate_session_registration_is_rejected() {
    let challenge = challenge();

    let mut store = SessionStore::new();

    store.register(challenge.clone()).unwrap();

    assert_eq!(
        store.register(challenge),
        Err(ProtocolError::DuplicateSession)
    );
}
