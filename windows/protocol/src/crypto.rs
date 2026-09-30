use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};

use crate::error::ProtocolError;
use crate::messages::LoginChallenge;
use crate::transcript::login_signature_transcript;

pub const P256_SIGNATURE_LEN: usize = 64;
pub const P256_PUBLIC_KEY_LEN: usize = 65;

pub fn sign_login_challenge(
    signing_key: &SigningKey,
    challenge: &LoginChallenge,
) -> Result<[u8; P256_SIGNATURE_LEN], ProtocolError> {
    let transcript = login_signature_transcript(challenge)?;

    let signature: Signature = signing_key.sign(&transcript);

    // Normalize to low-S form so PhoneKey uses one canonical signature form.
    let signature = signature.normalize_s();

    let bytes = signature.to_bytes();

    let mut output = [0u8; P256_SIGNATURE_LEN];
    output.copy_from_slice(bytes.as_ref());

    Ok(output)
}

pub fn verify_login_challenge(
    public_key_sec1: &[u8],
    challenge: &LoginChallenge,
    signature_bytes: &[u8],
) -> Result<(), ProtocolError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| ProtocolError::InvalidCryptoKey)?;

    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| ProtocolError::InvalidSignature)?;

    // Reject high-S signatures.
    let normalized = signature.normalize_s();

    if normalized != signature {
        return Err(ProtocolError::InvalidSignature);
    }

    let transcript = login_signature_transcript(challenge)?;

    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| ProtocolError::InvalidSignature)
}

pub fn public_key_sec1(signing_key: &SigningKey) -> [u8; P256_PUBLIC_KEY_LEN] {
    let encoded = signing_key.verifying_key().to_sec1_point(false);

    let mut output = [0u8; P256_PUBLIC_KEY_LEN];
    output.copy_from_slice(encoded.as_ref());

    output
}
