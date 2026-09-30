//! Independently protected lost-phone recovery copy of one file key.
//! A production UI must display the random recovery key once and verify the
//! user saved it before any original file may be deliberately removed.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::TryRngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::{KEY_LEN, VaultError};

const MAGIC: &[u8; 4] = b"PKR1";
const DOMAIN: &[u8] = b"PHONEKEY-FILE-RECOVERY-V1\x00";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const RECOVERY_RECORD_LEN: usize = 4 + NONCE_LEN + KEY_LEN + TAG_LEN;

pub fn new_recovery_key() -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng
        .try_fill_bytes(key.as_mut())
        .map_err(|_| VaultError::RandomUnavailable)?;
    Ok(key)
}

fn aad(file_sha256: &[u8; 32]) -> Vec<u8> {
    let mut result = Vec::with_capacity(DOMAIN.len() + file_sha256.len());
    result.extend_from_slice(DOMAIN);
    result.extend_from_slice(file_sha256);
    result
}

pub fn wrap_for_recovery(
    file_key: &[u8; KEY_LEN],
    file_sha256: &[u8; 32],
    recovery_key: &[u8; KEY_LEN],
) -> Result<[u8; RECOVERY_RECORD_LEN], VaultError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| VaultError::RandomUnavailable)?;
    let cipher = Aes256Gcm::new_from_slice(recovery_key).expect("fixed AES key length");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: file_key,
                aad: &aad(file_sha256),
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let mut record = [0u8; RECOVERY_RECORD_LEN];
    record[..4].copy_from_slice(MAGIC);
    record[4..4 + NONCE_LEN].copy_from_slice(&nonce);
    record[4 + NONCE_LEN..].copy_from_slice(&ciphertext);
    Ok(record)
}

pub fn unwrap_with_recovery_key(
    record: &[u8],
    file_sha256: &[u8; 32],
    recovery_key: &[u8; KEY_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    if record.len() != RECOVERY_RECORD_LEN || &record[..4] != MAGIC {
        return Err(VaultError::InvalidFormat);
    }
    let cipher = Aes256Gcm::new_from_slice(recovery_key).expect("fixed AES key length");
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&record[4..4 + NONCE_LEN]),
                Payload {
                    msg: &record[4 + NONCE_LEN..],
                    aad: &aad(file_sha256),
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
    fn recovery_opens_only_with_correct_code_and_file() {
        let file_key = new_file_key().unwrap();
        let recovery = new_recovery_key().unwrap();
        let other = new_recovery_key().unwrap();
        let hash = [9u8; 32];
        let record = wrap_for_recovery(&file_key, &hash, &recovery).unwrap();
        assert_eq!(
            *unwrap_with_recovery_key(&record, &hash, &recovery).unwrap(),
            *file_key
        );
        assert_eq!(
            unwrap_with_recovery_key(&record, &hash, &other),
            Err(VaultError::AuthenticationFailed)
        );
        assert_eq!(
            unwrap_with_recovery_key(&record, &[8u8; 32], &recovery),
            Err(VaultError::AuthenticationFailed)
        );
    }

    #[test]
    fn altered_record_is_rejected() {
        let file_key = new_file_key().unwrap();
        let recovery = new_recovery_key().unwrap();
        let hash = [9u8; 32];
        let record = wrap_for_recovery(&file_key, &hash, &recovery).unwrap();
        for offset in [0, 4, RECOVERY_RECORD_LEN - 1] {
            let mut changed = record;
            changed[offset] ^= 1;
            assert!(unwrap_with_recovery_key(&changed, &hash, &recovery).is_err());
        }
        assert_eq!(
            unwrap_with_recovery_key(&record[..RECORD_SHORT], &hash, &recovery),
            Err(VaultError::InvalidFormat)
        );
    }

    const RECORD_SHORT: usize = RECOVERY_RECORD_LEN - 1;
}
