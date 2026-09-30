//! Authenticated file-content envelope for a future phone-gated file vault.
//! This crate has no CLI; file operations preserve originals and write complete
//! packages. Phone approval and key custody must be integrated before real use.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::TryRngCore;
use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

pub mod approved_open;
#[cfg(windows)]
mod ble_lifecycle;
#[cfg(windows)]
pub mod file_ble;
pub mod files;
pub mod key_return;
pub mod key_wrap;
#[cfg(windows)]
pub mod live_open;
pub mod package;
pub mod phone_binding;
pub mod qr_image;
pub mod recovery;
pub mod recovery_code;
pub mod stream_package;
pub mod trusted_state;

pub const KEY_LEN: usize = 32;
/// Legacy PKP1/in-memory envelope limit. New PKP2 file encryption uses
/// stream_package::MAX_SOURCE_LEN and never allocates the whole source.
pub const MAX_PLAINTEXT_LEN: usize = 16 * 1024 * 1024;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + 3 + NONCE_LEN + 8;
const MAGIC: [u8; 4] = *b"PKVF";
const VERSION: u8 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("operating system randomness unavailable")]
    RandomUnavailable,
    #[error("file exceeds the legacy in-memory size limit")]
    TooLarge,
    #[error("invalid encrypted file format")]
    InvalidFormat,
    #[error("encrypted file authentication failed")]
    AuthenticationFailed,
}

/// Generate a new key for exactly one file. The caller must wrap this key
/// under phone-held and recovery credentials before persisting the envelope.
pub fn new_file_key() -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng
        .try_fill_bytes(key.as_mut())
        .map_err(|_| VaultError::RandomUnavailable)?;
    Ok(key)
}

/// Encrypt a bounded byte buffer with a unique per-file key.
/// The header is authenticated as AAD, including version, nonce and length.
pub fn seal(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, VaultError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(VaultError::TooLarge);
    }
    let mut nonce = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| VaultError::RandomUnavailable)?;
    let mut envelope = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN);
    envelope.extend_from_slice(&MAGIC);
    envelope.push(VERSION);
    envelope.extend_from_slice(&[0u8; 3]);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());
    let cipher = Aes256Gcm::new_from_slice(key).expect("fixed AES-256 key length");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &envelope,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Return plaintext only after complete length and authentication checks.
pub fn open(envelope: &[u8], key: &[u8; KEY_LEN]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if envelope.len() < HEADER_LEN + TAG_LEN
        || envelope[..4] != MAGIC
        || envelope[4] != VERSION
        || envelope[5..8] != [0u8; 3]
    {
        return Err(VaultError::InvalidFormat);
    }
    let length_bytes: [u8; 8] = envelope[20..28]
        .try_into()
        .map_err(|_| VaultError::InvalidFormat)?;
    let plaintext_len =
        usize::try_from(u64::from_be_bytes(length_bytes)).map_err(|_| VaultError::TooLarge)?;
    if plaintext_len > MAX_PLAINTEXT_LEN {
        return Err(VaultError::TooLarge);
    }
    if envelope.len() != HEADER_LEN + plaintext_len + TAG_LEN {
        return Err(VaultError::InvalidFormat);
    }
    let cipher = Aes256Gcm::new_from_slice(key).expect("fixed AES-256 key length");
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&envelope[8..20]),
            Payload {
                msg: &envelope[HEADER_LEN..],
                aad: &envelope[..HEADER_LEN],
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_binary_data_and_empty_data() {
        let key = new_file_key().unwrap();
        for plaintext in [b"\0document\xff".as_slice(), b"".as_slice()] {
            let encrypted = seal(plaintext, &key).unwrap();
            if !plaintext.is_empty() {
                assert_ne!(
                    &encrypted[HEADER_LEN..HEADER_LEN + plaintext.len()],
                    plaintext
                );
            }
            assert_eq!(open(&encrypted, &key).unwrap().as_slice(), plaintext);
        }
    }

    #[test]
    fn each_encryption_uses_a_new_nonce() {
        let key = new_file_key().unwrap();
        let first = seal(b"same bytes", &key).unwrap();
        let second = seal(b"same bytes", &key).unwrap();
        assert_ne!(&first[8..20], &second[8..20]);
        assert_ne!(first, second);
    }

    #[test]
    fn wrong_key_and_modified_ciphertext_fail() {
        let key = new_file_key().unwrap();
        let other = new_file_key().unwrap();
        let mut encrypted = seal(b"private", &key).unwrap();
        assert_eq!(
            open(&encrypted, &other),
            Err(VaultError::AuthenticationFailed)
        );
        encrypted[HEADER_LEN] ^= 1;
        assert_eq!(
            open(&encrypted, &key),
            Err(VaultError::AuthenticationFailed)
        );
        let mut tag_changed = seal(b"private", &key).unwrap();
        *tag_changed.last_mut().unwrap() ^= 1;
        assert_eq!(
            open(&tag_changed, &key),
            Err(VaultError::AuthenticationFailed)
        );
    }

    #[test]
    fn modified_header_and_trailing_bytes_fail() {
        let key = new_file_key().unwrap();
        let encrypted = seal(b"private", &key).unwrap();
        for offset in [4, 8, 20, 27] {
            let mut changed = encrypted.clone();
            changed[offset] ^= 1;
            assert!(open(&changed, &key).is_err());
        }
        let mut extended = encrypted.clone();
        extended.push(0);
        assert_eq!(open(&extended, &key), Err(VaultError::InvalidFormat));
        assert_eq!(
            open(&encrypted[..HEADER_LEN], &key),
            Err(VaultError::InvalidFormat)
        );
        let mut wrong_magic = encrypted.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(open(&wrong_magic, &key), Err(VaultError::InvalidFormat));
    }

    #[test]
    fn oversize_and_malformed_length_are_rejected() {
        let key = new_file_key().unwrap();
        let mut encrypted = seal(b"x", &key).unwrap();
        encrypted[20..28].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(open(&encrypted, &key), Err(VaultError::TooLarge));
        assert_eq!(
            seal(&vec![0u8; MAX_PLAINTEXT_LEN + 1], &key),
            Err(VaultError::TooLarge)
        );
    }
}
