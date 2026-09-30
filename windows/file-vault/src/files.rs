//! File operations for the complete phone-and-recovery package.
//! Normal export requires a verified phone proof; recovery uses the saved code.

use phonekey_protocol::types::DeviceId;
use rand::TryRngCore;
use rand::rngs::OsRng;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::phone_binding::{self, BindingError};
use crate::recovery;
use crate::stream_package::{self, Metadata};
use crate::{KEY_LEN, MAX_PLAINTEXT_LEN};

#[derive(Debug, Error)]
pub enum SignedEncryptError {
    #[error("file-key pairing is invalid: {0}")]
    Binding(#[from] BindingError),
    #[error("file encryption failed: {0}")]
    Io(#[from] io::Error),
}

/// Save and verify a new complete package, leaving the original in place.
/// The caller must ensure the user saved the recovery key first.
pub fn encrypt_package_to_new_file(
    source: &Path,
    destination: &Path,
    phone_public_sec1: &[u8],
    recovery_key: &[u8; KEY_LEN],
) -> io::Result<()> {
    stream_package::seal_to_new_file(source, destination, phone_public_sec1, recovery_key)
}

/// Normal encryption entry point: refuse any phone agreement key not signed
/// by the already trusted PhoneKey identity. The caller separately confirms
/// that the recovery code has been saved before invoking this operation.
pub fn encrypt_with_signed_phone_binding(
    source: &Path,
    destination: &Path,
    signed_binding: &str,
    trusted_phone_id: DeviceId,
    trusted_signing_public_sec1: &[u8],
    recovery_key: &[u8; KEY_LEN],
) -> Result<(), SignedEncryptError> {
    let phone_public = phone_binding::verify_export(
        signed_binding,
        trusted_phone_id,
        trusted_signing_public_sec1,
    )?;
    encrypt_package_to_new_file(source, destination, &phone_public, recovery_key)?;
    Ok(())
}

/// Exceptional lost-phone route; returns zeroizing plaintext in memory.
/// A future UI must require explicit entry of the saved recovery key.
pub fn recover_package_in_memory(
    source: &Path,
    recovery_key: &[u8; KEY_LEN],
) -> io::Result<Zeroizing<Vec<u8>>> {
    let metadata = stream_package::read_metadata(source)?;
    if metadata.plaintext_len > MAX_PLAINTEXT_LEN as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file is too large to hold in memory",
        ));
    }
    let file_key = recovery::unwrap_with_recovery_key(
        &metadata.recovery_wrap,
        &metadata.envelope_sha256,
        recovery_key,
    )
    .map_err(io::Error::other)?;
    decrypt_package_to_memory(source, &metadata, &file_key, MAX_PLAINTEXT_LEN)
}

pub fn decrypt_package_to_memory(
    source: &Path,
    metadata: &Metadata,
    file_key: &[u8; KEY_LEN],
    max_len: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    if metadata.plaintext_len > max_len as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file is too large for this viewer",
        ));
    }
    let mut plaintext = Zeroizing::new(Vec::with_capacity(metadata.plaintext_len as usize));
    stream_package::decrypt_to_writer(source, metadata, file_key, &mut *plaintext)?;
    Ok(plaintext)
}

fn verified_export(
    source: &Path,
    destination: &Path,
    metadata: &Metadata,
    file_key: &[u8; KEY_LEN],
) -> io::Result<()> {
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "plaintext destination exists",
        ));
    }
    let name = destination
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing output filename"))?;
    let mut staged = None;
    for _ in 0..16 {
        let mut random = [0u8; 8];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(io::Error::other)?;
        let path = destination.with_file_name(format!(
            ".{}.phonekey-{:016x}.tmp",
            name.to_string_lossy(),
            u64::from_be_bytes(random)
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => {
                staged = Some((path, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let (staged_path, mut output) = staged.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create unique staging file",
        )
    })?;
    let result = (|| {
        stream_package::decrypt_to_writer(source, metadata, file_key, &mut output)?;
        output.sync_all()?;
        drop(output);
        // Hard-link creation refuses an existing destination and exposes only
        // a fully verified file, never a partly decrypted one.
        fs::hard_link(&staged_path, destination)?;
        Ok(())
    })();
    let _ = fs::remove_file(&staged_path);
    result
}

pub fn export_package_to_new_file(
    source: &Path,
    destination: &Path,
    metadata: &Metadata,
    file_key: &[u8; KEY_LEN],
) -> io::Result<()> {
    verified_export(source, destination, metadata, file_key)
}

pub fn recover_package_to_new_file(
    source: &Path,
    destination: &Path,
    recovery_key: &[u8; KEY_LEN],
) -> io::Result<()> {
    let metadata = stream_package::read_metadata(source)?;
    let file_key = recovery::unwrap_with_recovery_key(
        &metadata.recovery_wrap,
        &metadata.envelope_sha256,
        recovery_key,
    )
    .map_err(io::Error::other)?;
    verified_export(source, destination, &metadata, &file_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::new_recovery_key;
    use p256::SecretKey;

    #[test]
    fn package_file_round_trip_preserves_source_and_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("original.txt");
        let encrypted = dir.path().join("original.pkp");
        fs::write(&source, b"dummy document").unwrap();
        let phone = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let recovery = new_recovery_key().unwrap();
        encrypt_package_to_new_file(
            &source,
            &encrypted,
            &phone.public_key().to_sec1_bytes(),
            &recovery,
        )
        .unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"dummy document");
        assert_eq!(
            recover_package_in_memory(&encrypted, &recovery)
                .unwrap()
                .as_slice(),
            b"dummy document"
        );
        assert_eq!(
            encrypt_package_to_new_file(
                &source,
                &encrypted,
                &phone.public_key().to_sec1_bytes(),
                &recovery
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn wrong_key_and_tampering_return_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let encrypted = dir.path().join("cipher");
        fs::write(&source, b"dummy document").unwrap();
        let phone = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let recovery = new_recovery_key().unwrap();
        encrypt_package_to_new_file(
            &source,
            &encrypted,
            &phone.public_key().to_sec1_bytes(),
            &recovery,
        )
        .unwrap();
        assert!(recover_package_in_memory(&encrypted, &new_recovery_key().unwrap()).is_err());
        let mut bytes = fs::read(&encrypted).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&encrypted, bytes).unwrap();
        assert!(recover_package_in_memory(&encrypted, &recovery).is_err());
    }
}
