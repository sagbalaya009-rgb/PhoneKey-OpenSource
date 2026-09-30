use p256::ecdsa::SigningKey;

use crate::crypto::{public_key_sec1, sign_login_challenge, verify_login_challenge};
use crate::messages::{
    LoginChallenge, LoginOperation, decode_login_challenge, encode_login_challenge,
};
use crate::proof::{
    create_login_proof, decode_login_proof, encode_login_proof, verify_login_proof,
};
use crate::transcript::login_signature_transcript;
use crate::types::{DEVICE_ID_LEN, DeviceId, NONCE_LEN, Nonce, SESSION_ID_LEN, SessionId};

const CHALLENGE_HEX: &str = "a9010102010350111111111111111111111111111111110450222222222222222222222222222222220558203333333333333333333333333333333333333333333333333333333333333333061a000f4240071a00102ca008010958204444444444444444444444444444444444444444444444444444444444444444";

const TRANSCRIPT_HEX: &str = "50484f4e454b45592d4c4f47494e2d5349474e41545552452d563100a9010102010350111111111111111111111111111111110450222222222222222222222222222222220558203333333333333333333333333333333333333333333333333333333333333333061a000f4240071a00102ca008010958204444444444444444444444444444444444444444444444444444444444444444";

const PUBLIC_KEY_HEX: &str = "04515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354";

const SIGNATURE_HEX: &str = "333c32a289686862084887c907d9c195037b9655eef895ce4fabab2251932ff52dca47574e8506e9971075c23d45b560203f9f7e2cfd5792d8e0cf84a5d5db5a";

const PROOF_HEX: &str = "a5010102020350aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa045022222222222222222222222222222222055840333c32a289686862084887c907d9c195037b9655eef895ce4fabab2251932ff52dca47574e8506e9971075c23d45b560203f9f7e2cfd5792d8e0cf84a5d5db5a";

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
fn golden_challenge_is_frozen() {
    let encoded = encode_login_challenge(&challenge()).unwrap();

    assert_eq!(hex::encode(encoded), CHALLENGE_HEX);
}

#[test]
fn golden_transcript_is_frozen() {
    let transcript = login_signature_transcript(&challenge()).unwrap();

    assert_eq!(hex::encode(transcript), TRANSCRIPT_HEX);
}

#[test]
fn golden_public_key_is_frozen() {
    let key = signing_key();
    let public_key = public_key_sec1(&key);

    assert_eq!(hex::encode(public_key), PUBLIC_KEY_HEX);
}

#[test]
fn golden_signature_is_frozen() {
    let key = signing_key();

    let signature = sign_login_challenge(&key, &challenge()).unwrap();

    assert_eq!(hex::encode(signature), SIGNATURE_HEX);
}

#[test]
fn golden_proof_is_frozen() {
    let key = signing_key();

    let proof = create_login_proof(&key, android_device_id(), &challenge()).unwrap();

    let encoded = encode_login_proof(&proof).unwrap();

    assert_eq!(hex::encode(encoded), PROOF_HEX);
}

#[test]
fn frozen_challenge_decodes_correctly() {
    let bytes = hex::decode(CHALLENGE_HEX).unwrap();

    let decoded = decode_login_challenge(&bytes).unwrap();

    assert_eq!(decoded, challenge());
}

#[test]
fn frozen_signature_verifies() {
    let public_key = hex::decode(PUBLIC_KEY_HEX).unwrap();
    let signature = hex::decode(SIGNATURE_HEX).unwrap();

    assert_eq!(
        verify_login_challenge(&public_key, &challenge(), &signature),
        Ok(())
    );
}

#[test]
fn frozen_proof_decodes_and_verifies() {
    let bytes = hex::decode(PROOF_HEX).unwrap();
    let proof = decode_login_proof(&bytes).unwrap();

    let public_key = hex::decode(PUBLIC_KEY_HEX).unwrap();

    assert_eq!(
        verify_login_proof(&proof, &android_device_id(), &public_key, &challenge(),),
        Ok(())
    );
}
