use crate::messages::{LoginChallenge, LoginOperation};
use crate::transcript::login_signature_transcript;
use crate::types::{DEVICE_ID_LEN, DeviceId, NONCE_LEN, Nonce, SESSION_ID_LEN, SessionId};

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
fn transcript_has_login_domain_prefix() {
    let transcript = login_signature_transcript(&challenge()).unwrap();

    assert!(transcript.starts_with(b"PHONEKEY-LOGIN-SIGNATURE-V1\x00"));
}

#[test]
fn same_challenge_produces_same_transcript() {
    let first = login_signature_transcript(&challenge()).unwrap();
    let second = login_signature_transcript(&challenge()).unwrap();

    assert_eq!(first, second);
}

#[test]
fn changing_nonce_changes_transcript() {
    let first = challenge();
    let mut second = challenge();

    second.nonce = Nonce([0x99; NONCE_LEN]);

    assert_ne!(
        login_signature_transcript(&first).unwrap(),
        login_signature_transcript(&second).unwrap()
    );
}

#[test]
fn changing_session_changes_transcript() {
    let first = challenge();
    let mut second = challenge();

    second.session_id = SessionId([0xaa; SESSION_ID_LEN]);

    assert_ne!(
        login_signature_transcript(&first).unwrap(),
        login_signature_transcript(&second).unwrap()
    );
}

#[test]
fn changing_account_binding_changes_transcript() {
    let first = challenge();
    let mut second = challenge();

    second.account_binding = vec![0x55; 32];

    assert_ne!(
        login_signature_transcript(&first).unwrap(),
        login_signature_transcript(&second).unwrap()
    );
}

#[test]
fn changing_operation_changes_transcript() {
    let first = challenge();
    let mut second = challenge();

    second.operation = LoginOperation::Unlock;

    assert_ne!(
        login_signature_transcript(&first).unwrap(),
        login_signature_transcript(&second).unwrap()
    );
}
