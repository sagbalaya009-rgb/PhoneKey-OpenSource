//! Versioned ECIES-style wrapping of one file key to a phone ECDH public key.
//! The Android Keystore agreement path and recovery copy must be finished
//! before this is used for real documents.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{KEY_LEN, VaultError};

const MAGIC: &[u8; 4] = b"PKW1";
const DOMAIN: &[u8] = b"PHONEKEY-FILE-WRAP-V1\x00";
const PUBLIC_LEN: usize = 65;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const WRAP_RECORD_LEN: usize = 4 + PUBLIC_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;

fn new_ephemeral_secret() -> Result<SecretKey, VaultError> {
    for _ in 0..16 {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        OsRng
            .try_fill_bytes(bytes.as_mut())
            .map_err(|_| VaultError::RandomUnavailable)?;
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
    Err(VaultError::RandomUnavailable)
}

fn derive_key(
    shared_secret: &[u8],
    file_sha256: &[u8; 32],
    ephemeral_public: &[u8],
    phone_public: &[u8],
) -> Zeroizing<[u8; KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(Some(file_sha256), shared_secret);
    let mut info = Vec::with_capacity(DOMAIN.len() + 2 * PUBLIC_LEN);
    info.extend_from_slice(DOMAIN);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(phone_public);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(&info, key.as_mut())
        .expect("32-byte HKDF output");
    key
}

fn aad(file_sha256: &[u8; 32], ephemeral_public: &[u8], phone_public: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(DOMAIN.len() + 32 + 2 * PUBLIC_LEN);
    value.extend_from_slice(DOMAIN);
    value.extend_from_slice(file_sha256);
    value.extend_from_slice(ephemeral_public);
    value.extend_from_slice(phone_public);
    value
}

/// Encrypt a unique 32-byte file key for the phone's separate ECDH key.
/// `file_sha256` hashes the complete encrypted-file envelope.
pub fn wrap_for_phone(
    file_key: &[u8; KEY_LEN],
    file_sha256: &[u8; 32],
    phone_public_sec1: &[u8],
) -> Result<[u8; WRAP_RECORD_LEN], VaultError> {
    let ephemeral = new_ephemeral_secret()?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| VaultError::RandomUnavailable)?;
    wrap_with_params(file_key, file_sha256, phone_public_sec1, &ephemeral, &nonce)
}

fn wrap_with_params(
    file_key: &[u8; KEY_LEN],
    file_sha256: &[u8; 32],
    phone_public_sec1: &[u8],
    ephemeral: &SecretKey,
    nonce: &[u8; NONCE_LEN],
) -> Result<[u8; WRAP_RECORD_LEN], VaultError> {
    let phone_public =
        PublicKey::from_sec1_bytes(phone_public_sec1).map_err(|_| VaultError::InvalidFormat)?;
    let ephemeral_public = ephemeral.public_key().to_sec1_bytes();
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), phone_public.as_affine());
    let mut shared_bytes = Zeroizing::new([0u8; KEY_LEN]);
    shared_bytes.copy_from_slice(shared.raw_secret_bytes().as_slice());
    let wrapping_key = derive_key(
        shared_bytes.as_ref(),
        file_sha256,
        &ephemeral_public,
        phone_public_sec1,
    );
    let cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref()).expect("fixed AES key length");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: file_key,
                aad: &aad(file_sha256, &ephemeral_public, phone_public_sec1),
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let mut record = [0u8; WRAP_RECORD_LEN];
    record[..4].copy_from_slice(MAGIC);
    record[4..4 + PUBLIC_LEN].copy_from_slice(&ephemeral_public);
    record[4 + PUBLIC_LEN..4 + PUBLIC_LEN + NONCE_LEN].copy_from_slice(nonce);
    record[4 + PUBLIC_LEN + NONCE_LEN..].copy_from_slice(&ciphertext);
    Ok(record)
}

/// Test-side equivalent of the Android Keystore unwrap operation. Production
/// phone private keys must never be exported to Windows.
pub fn unwrap_with_phone_secret(
    record: &[u8],
    file_sha256: &[u8; 32],
    phone_secret: &SecretKey,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    if record.len() != WRAP_RECORD_LEN || &record[..4] != MAGIC {
        return Err(VaultError::InvalidFormat);
    }
    let ephemeral_public_bytes = &record[4..4 + PUBLIC_LEN];
    let ephemeral_public = PublicKey::from_sec1_bytes(ephemeral_public_bytes)
        .map_err(|_| VaultError::InvalidFormat)?;
    let phone_public = phone_secret.public_key().to_sec1_bytes();
    let shared = diffie_hellman(
        phone_secret.to_nonzero_scalar(),
        ephemeral_public.as_affine(),
    );
    let mut shared_bytes = Zeroizing::new([0u8; KEY_LEN]);
    shared_bytes.copy_from_slice(shared.raw_secret_bytes().as_slice());
    let wrapping_key = derive_key(
        shared_bytes.as_ref(),
        file_sha256,
        ephemeral_public_bytes,
        &phone_public,
    );
    let cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref()).expect("fixed AES key length");
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&record[4 + PUBLIC_LEN..4 + PUBLIC_LEN + NONCE_LEN]),
                Payload {
                    msg: &record[4 + PUBLIC_LEN + NONCE_LEN..],
                    aad: &aad(file_sha256, ephemeral_public_bytes, &phone_public),
                },
            )
            .map_err(|_| VaultError::AuthenticationFailed)?,
    );
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::new_file_key;

    #[test]
    fn deterministic_cross_platform_vector() {
        let phone = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let ephemeral = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let phone_public = phone.public_key().to_sec1_bytes();
        let record = wrap_with_params(
            &[5u8; 32],
            &[9u8; 32],
            &phone_public,
            &ephemeral,
            &[4u8; NONCE_LEN],
        )
        .unwrap();
        assert_eq!(
            *unwrap_with_phone_secret(&record, &[9u8; 32], &phone).unwrap(),
            [5u8; 32]
        );
        println!(
            "PHONE_PUBLIC={}",
            phone_public
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        println!(
            "WRAP_RECORD={}",
            record
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }

    #[test]
    fn phone_secret_recovers_key_only_for_same_file() {
        let phone = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let other = SecretKey::from_slice(&[8u8; 32]).unwrap();
        let file_key = new_file_key().unwrap();
        let file_hash = [9u8; 32];
        let record =
            wrap_for_phone(&file_key, &file_hash, &phone.public_key().to_sec1_bytes()).unwrap();
        assert_eq!(
            *unwrap_with_phone_secret(&record, &file_hash, &phone).unwrap(),
            *file_key
        );
        assert_eq!(
            unwrap_with_phone_secret(&record, &file_hash, &other),
            Err(VaultError::AuthenticationFailed)
        );
        assert_eq!(
            unwrap_with_phone_secret(&record, &[1u8; 32], &phone),
            Err(VaultError::AuthenticationFailed)
        );
    }

    #[test]
    fn tampering_and_malformed_keys_fail() {
        let phone = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let key = new_file_key().unwrap();
        let hash = [9u8; 32];
        assert_eq!(
            wrap_for_phone(&key, &hash, &[0u8; 65]),
            Err(VaultError::InvalidFormat)
        );
        let record = wrap_for_phone(&key, &hash, &phone.public_key().to_sec1_bytes()).unwrap();
        for offset in [0, 4, 69, WRAP_RECORD_LEN - 1] {
            let mut changed = record;
            changed[offset] ^= 1;
            assert!(unwrap_with_phone_secret(&changed, &hash, &phone).is_err());
        }
    }
}
