//! One-time encrypted return of a file key after phone approval.
//! The caller must bind the challenge digest to an authenticated QR and
//! verify the phone's signature over this exact record before opening it.

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

const MAGIC: &[u8; 4] = b"PKR1";
const DOMAIN: &[u8] = b"PHONEKEY-FILE-RETURN-V1\x00";
const PUBLIC_LEN: usize = 65;
const NONCE_LEN: usize = 12;
pub const RETURN_RECORD_LEN: usize = 4 + PUBLIC_LEN + NONCE_LEN + KEY_LEN + 16;

fn derived_key(
    shared: &[u8],
    challenge_sha256: &[u8; 32],
    ephemeral_public: &[u8],
    laptop_public: &[u8],
) -> Zeroizing<[u8; KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(Some(challenge_sha256), shared);
    let mut info = Vec::with_capacity(DOMAIN.len() + 2 * PUBLIC_LEN);
    info.extend_from_slice(DOMAIN);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(laptop_public);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(&info, key.as_mut())
        .expect("32-byte HKDF output");
    key
}

fn aad(challenge_sha256: &[u8; 32], ephemeral_public: &[u8], laptop_public: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(DOMAIN.len() + 32 + 2 * PUBLIC_LEN);
    value.extend_from_slice(DOMAIN);
    value.extend_from_slice(challenge_sha256);
    value.extend_from_slice(ephemeral_public);
    value.extend_from_slice(laptop_public);
    value
}

/// Used on the phone after fresh approval. The laptop return public key must
/// have been included in the QR-bound challenge.
pub fn seal_for_laptop(
    file_key: &[u8; KEY_LEN],
    challenge_sha256: &[u8; 32],
    laptop_public_sec1: &[u8],
) -> Result<[u8; RETURN_RECORD_LEN], VaultError> {
    let mut secret_bytes = Zeroizing::new([0u8; KEY_LEN]);
    OsRng
        .try_fill_bytes(secret_bytes.as_mut())
        .map_err(|_| VaultError::RandomUnavailable)?;
    let ephemeral =
        SecretKey::from_slice(secret_bytes.as_ref()).map_err(|_| VaultError::RandomUnavailable)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| VaultError::RandomUnavailable)?;
    seal_with_params(
        file_key,
        challenge_sha256,
        laptop_public_sec1,
        &ephemeral,
        &nonce,
    )
}

fn seal_with_params(
    file_key: &[u8; KEY_LEN],
    challenge_sha256: &[u8; 32],
    laptop_public_sec1: &[u8],
    ephemeral: &SecretKey,
    nonce: &[u8; NONCE_LEN],
) -> Result<[u8; RETURN_RECORD_LEN], VaultError> {
    let laptop_public =
        PublicKey::from_sec1_bytes(laptop_public_sec1).map_err(|_| VaultError::InvalidFormat)?;
    let ephemeral_public = ephemeral.public_key().to_sec1_bytes();
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), laptop_public.as_affine());
    let mut shared_bytes = Zeroizing::new([0u8; KEY_LEN]);
    shared_bytes.copy_from_slice(shared.raw_secret_bytes().as_slice());
    let wrapping_key = derived_key(
        shared_bytes.as_ref(),
        challenge_sha256,
        &ephemeral_public,
        laptop_public_sec1,
    );
    let cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref()).expect("fixed AES key length");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: file_key,
                aad: &aad(challenge_sha256, &ephemeral_public, laptop_public_sec1),
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let mut record = [0u8; RETURN_RECORD_LEN];
    record[..4].copy_from_slice(MAGIC);
    record[4..69].copy_from_slice(&ephemeral_public);
    record[69..81].copy_from_slice(nonce);
    record[81..].copy_from_slice(&ciphertext);
    Ok(record)
}

/// Used only after the one-use session gate verifies the phone proof.
pub fn open_on_laptop(
    record: &[u8],
    challenge_sha256: &[u8; 32],
    laptop_secret: &SecretKey,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    if record.len() != RETURN_RECORD_LEN || &record[..4] != MAGIC {
        return Err(VaultError::InvalidFormat);
    }
    let ephemeral_public =
        PublicKey::from_sec1_bytes(&record[4..69]).map_err(|_| VaultError::InvalidFormat)?;
    let laptop_public = laptop_secret.public_key().to_sec1_bytes();
    let shared = diffie_hellman(
        laptop_secret.to_nonzero_scalar(),
        ephemeral_public.as_affine(),
    );
    let mut shared_bytes = Zeroizing::new([0u8; KEY_LEN]);
    shared_bytes.copy_from_slice(shared.raw_secret_bytes().as_slice());
    let wrapping_key = derived_key(
        shared_bytes.as_ref(),
        challenge_sha256,
        &record[4..69],
        &laptop_public,
    );
    let cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref()).expect("fixed AES key length");
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&record[69..81]),
                Payload {
                    msg: &record[81..],
                    aad: &aad(challenge_sha256, &record[4..69], &laptop_public),
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

    #[test]
    fn return_record_is_bound_to_laptop_and_challenge() {
        let laptop = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let other = SecretKey::from_slice(&[8u8; 32]).unwrap();
        let record = seal_with_params(
            &[5; 32],
            &[9; 32],
            &laptop.public_key().to_sec1_bytes(),
            &SecretKey::from_slice(&[3u8; 32]).unwrap(),
            &[4; 12],
        )
        .unwrap();
        assert_eq!(
            *open_on_laptop(&record, &[9; 32], &laptop).unwrap(),
            [5; 32]
        );
        assert_eq!(
            open_on_laptop(&record, &[1; 32], &laptop),
            Err(VaultError::AuthenticationFailed)
        );
        assert_eq!(
            open_on_laptop(&record, &[9; 32], &other),
            Err(VaultError::AuthenticationFailed)
        );
        let mut changed = record;
        changed[128] ^= 1;
        assert_eq!(
            open_on_laptop(&changed, &[9; 32], &laptop),
            Err(VaultError::AuthenticationFailed)
        );
        println!(
            "RETURN_RECORD={}",
            record
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
}
