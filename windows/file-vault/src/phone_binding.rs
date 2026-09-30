//! Verify that the paired phone's signing identity authorized a distinct
//! Android Keystore file-agreement public key. This never accepts an unsigned
//! public key copied from a QR, clipboard, or USB debugging output.

use p256::PublicKey;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use phonekey_protocol::types::DeviceId;
use thiserror::Error;

const DOMAIN: &[u8] = b"PHONEKEY-FILE-BINDING-V1\0";
const PREFIX: &str = "PKB1";
const DEVICE_ID_HEX_LEN: usize = 32;
const PUBLIC_KEY_HEX_LEN: usize = 130;
const SIGNATURE_HEX_LEN: usize = 128;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("invalid file-key binding")]
    InvalidFormat,
    #[error("file-key binding is for another phone")]
    WrongPhone,
    #[error("file-key binding signature is invalid")]
    InvalidSignature,
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], BindingError> {
    if text.len() != 2 * N {
        return Err(BindingError::InvalidFormat);
    }
    let mut bytes = [0u8; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(BindingError::InvalidFormat)?;
        let low = hex_nibble(pair[1]).ok_or(BindingError::InvalidFormat)?;
        bytes[index] = high << 4 | low;
    }
    Ok(bytes)
}

pub fn binding_transcript(device_id: &DeviceId, agreement_public_sec1: &[u8; 65]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(DOMAIN.len() + 16 + 65);
    transcript.extend_from_slice(DOMAIN);
    transcript.extend_from_slice(&device_id.0);
    transcript.extend_from_slice(agreement_public_sec1);
    transcript
}

/// Verify a `PKB1` export against the already enrolled phone's signing key.
/// The returned key is suitable for wrapping a file key to that phone.
pub fn verify_export(
    export: &str,
    trusted_phone_id: DeviceId,
    trusted_signing_public_sec1: &[u8],
) -> Result<[u8; 65], BindingError> {
    let fields: Vec<&str> = export.trim().split('|').collect();
    if fields.len() != 4
        || fields[0] != PREFIX
        || fields[1].len() != DEVICE_ID_HEX_LEN
        || fields[2].len() != PUBLIC_KEY_HEX_LEN
        || fields[3].len() != SIGNATURE_HEX_LEN
    {
        return Err(BindingError::InvalidFormat);
    }
    let phone_id = DeviceId(decode_hex::<16>(fields[1])?);
    if phone_id != trusted_phone_id {
        return Err(BindingError::WrongPhone);
    }
    let public = decode_hex::<65>(fields[2])?;
    if public[0] != 4 || PublicKey::from_sec1_bytes(&public).is_err() {
        return Err(BindingError::InvalidFormat);
    }
    let signature = Signature::from_slice(&decode_hex::<64>(fields[3])?)
        .map_err(|_| BindingError::InvalidSignature)?;
    if signature.normalize_s() != signature {
        return Err(BindingError::InvalidSignature);
    }
    let trusted_key = VerifyingKey::from_sec1_bytes(trusted_signing_public_sec1)
        .map_err(|_| BindingError::InvalidFormat)?;
    trusted_key
        .verify(&binding_transcript(&phone_id, &public), &signature)
        .map_err(|_| BindingError::InvalidSignature)?;
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;
    use p256::ecdsa::{SigningKey, signature::Signer};

    fn lower_hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            result.push(DIGITS[(byte >> 4) as usize] as char);
            result.push(DIGITS[(byte & 15) as usize] as char);
        }
        result
    }

    #[test]
    fn accepts_only_binding_signed_by_the_enrolled_phone() {
        let phone_id = DeviceId([1; 16]);
        let signer = SigningKey::from_bytes((&[8; 32]).into()).unwrap();
        let agreement = SecretKey::from_slice(&[7; 32]).unwrap();
        let public: [u8; 65] = agreement
            .public_key()
            .to_sec1_bytes()
            .as_ref()
            .try_into()
            .unwrap();
        let signature: Signature = signer.sign(&binding_transcript(&phone_id, &public));
        let signature = signature.normalize_s();
        let export = format!(
            "PKB1|{}|{}|{}",
            lower_hex(&phone_id.0),
            lower_hex(&public),
            lower_hex(signature.to_bytes().as_ref())
        );
        let trusted = signer.verifying_key().to_sec1_point(false);
        assert_eq!(
            verify_export(&export, phone_id, trusted.as_bytes()).unwrap(),
            public
        );
        assert_eq!(
            verify_export(&export, DeviceId([2; 16]), trusted.as_bytes()),
            Err(BindingError::WrongPhone)
        );
        let mut altered = export.into_bytes();
        altered[50] = if altered[50] == b'0' { b'1' } else { b'0' };
        assert!(
            verify_export(
                std::str::from_utf8(&altered).unwrap(),
                phone_id,
                trusted.as_bytes()
            )
            .is_err()
        );
    }
}
