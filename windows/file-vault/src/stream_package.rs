//! PKP2: bounded-memory, authenticated file packages. PKP1 remains readable.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::key_wrap::{self, WRAP_RECORD_LEN};
use crate::package;
use crate::recovery::{self, RECOVERY_RECORD_LEN};
use crate::{KEY_LEN, VaultError, new_file_key, open};

pub const MAX_SOURCE_LEN: u64 = 1024 * 1024 * 1024 * 1024; // 1 TiB
const CHUNK_LEN: usize = 1024 * 1024;
const TAG_LEN: u64 = 16;
const HEADER_LEN: usize = 4 + 1 + 3 + 8 + 32;
const ENVELOPE_HEADER_LEN: usize = 4 + 1 + 3 + 4 + 8 + 4;
const PHONE_START: usize = HEADER_LEN;
const RECOVERY_START: usize = PHONE_START + WRAP_RECORD_LEN;
const ENVELOPE_START: usize = RECOVERY_START + RECOVERY_RECORD_LEN;
const MAGIC: &[u8; 4] = b"PKP2";
const ENVELOPE_MAGIC: &[u8; 4] = b"PKV2";

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, VaultError::InvalidFormat)
}
fn auth_failed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, VaultError::AuthenticationFailed)
}
fn too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "file exceeds the 1 TiB streaming limit",
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    Legacy,
    Streaming,
}

pub struct Metadata {
    pub version: Version,
    pub phone_wrap: [u8; WRAP_RECORD_LEN],
    pub recovery_wrap: [u8; RECOVERY_RECORD_LEN],
    pub envelope_sha256: [u8; 32],
    /// PKP1 binds the whole package. PKP2 binds its immutable prefix; the
    /// ciphertext is checked against envelope_sha256 while decrypting.
    pub identity: [u8; 32],
    pub plaintext_len: u64,
}

fn chunks_for(plaintext_len: u64) -> u64 {
    if plaintext_len == 0 {
        1
    } else {
        (plaintext_len - 1) / CHUNK_LEN as u64 + 1
    }
}

fn envelope_len(plaintext_len: u64) -> io::Result<u64> {
    if plaintext_len > MAX_SOURCE_LEN {
        return Err(too_large());
    }
    (ENVELOPE_HEADER_LEN as u64)
        .checked_add(plaintext_len)
        .and_then(|v| v.checked_add(chunks_for(plaintext_len) * TAG_LEN))
        .ok_or_else(too_large)
}

fn make_envelope_header(plaintext_len: u64, nonce_prefix: [u8; 4]) -> [u8; ENVELOPE_HEADER_LEN] {
    let mut header = [0u8; ENVELOPE_HEADER_LEN];
    header[..4].copy_from_slice(ENVELOPE_MAGIC);
    header[4] = 2;
    header[8..12].copy_from_slice(&nonce_prefix);
    header[12..20].copy_from_slice(&plaintext_len.to_be_bytes());
    header[20..24].copy_from_slice(&(CHUNK_LEN as u32).to_be_bytes());
    header
}

fn chunk_nonce(header: &[u8; ENVELOPE_HEADER_LEN], index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&header[8..12]);
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn chunk_aad(header: &[u8; ENVELOPE_HEADER_LEN], index: u64, len: usize) -> [u8; 36] {
    let mut aad = [0u8; 36];
    aad[..ENVELOPE_HEADER_LEN].copy_from_slice(header);
    aad[24..32].copy_from_slice(&index.to_be_bytes());
    aad[32..].copy_from_slice(&(len as u32).to_be_bytes());
    aad
}

fn expected_chunk_len(plaintext_len: u64, index: u64) -> usize {
    let left = plaintext_len.saturating_sub(index * CHUNK_LEN as u64);
    left.min(CHUNK_LEN as u64) as usize
}

fn read_legacy(path: &Path) -> io::Result<Metadata> {
    let file = File::open(path)?;
    if file.metadata()?.len() > package::MAX_PACKAGE_LEN as u64 {
        return Err(too_large());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(package::MAX_PACKAGE_LEN as u64 + 1)
        .read_to_end(&mut bytes)?;
    let parsed = package::parse(&bytes).map_err(io::Error::other)?;
    let plaintext_len = u64::from_be_bytes(parsed.envelope[20..28].try_into().unwrap());
    Ok(Metadata {
        version: Version::Legacy,
        phone_wrap: parsed.phone_wrap.try_into().unwrap(),
        recovery_wrap: parsed.recovery_wrap.try_into().unwrap(),
        envelope_sha256: parsed.envelope_sha256,
        identity: Sha256::digest(bytes.as_slice()).into(),
        plaintext_len,
    })
}

pub fn read_metadata(path: &Path) -> io::Result<Metadata> {
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if &magic == b"PKP1" {
        return read_legacy(path);
    }
    if &magic != MAGIC {
        return Err(invalid());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut prefix = [0u8; ENVELOPE_START + ENVELOPE_HEADER_LEN];
    file.read_exact(&mut prefix)?;
    if prefix[4] != 2 || prefix[5..8] != [0; 3] {
        return Err(invalid());
    }
    let declared_envelope_len = u64::from_be_bytes(prefix[8..16].try_into().unwrap());
    let mut envelope_sha256 = [0u8; 32];
    envelope_sha256.copy_from_slice(&prefix[16..48]);
    let envelope_header = &prefix[ENVELOPE_START..];
    if &envelope_header[..4] != ENVELOPE_MAGIC
        || envelope_header[4] != 2
        || envelope_header[5..8] != [0; 3]
        || u32::from_be_bytes(envelope_header[20..24].try_into().unwrap()) != CHUNK_LEN as u32
    {
        return Err(invalid());
    }
    let plaintext_len = u64::from_be_bytes(envelope_header[12..20].try_into().unwrap());
    let expected_envelope_len = envelope_len(plaintext_len)?;
    let expected_file_len = (ENVELOPE_START as u64)
        .checked_add(expected_envelope_len)
        .ok_or_else(too_large)?;
    if declared_envelope_len != expected_envelope_len || file.metadata()?.len() != expected_file_len
    {
        return Err(invalid());
    }
    Ok(Metadata {
        version: Version::Streaming,
        phone_wrap: prefix[PHONE_START..RECOVERY_START].try_into().unwrap(),
        recovery_wrap: prefix[RECOVERY_START..ENVELOPE_START].try_into().unwrap(),
        envelope_sha256,
        identity: Sha256::digest(&prefix).into(),
        plaintext_len,
    })
}

pub fn seal_to_new_file(
    source: &Path,
    destination: &Path,
    phone_public_sec1: &[u8],
    recovery_key: &[u8; KEY_LEN],
) -> io::Result<()> {
    let mut input = File::open(source)?;
    let input_meta = input.metadata()?;
    if !input_meta.is_file() {
        return Err(invalid());
    }
    let plaintext_len = input_meta.len();
    let ciphertext_len = envelope_len(plaintext_len)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let result = (|| -> io::Result<()> {
        let file_key = new_file_key().map_err(io::Error::other)?;
        let mut nonce_prefix = [0u8; 4];
        OsRng
            .try_fill_bytes(&mut nonce_prefix)
            .map_err(|_| io::Error::other(VaultError::RandomUnavailable))?;
        let envelope_header = make_envelope_header(plaintext_len, nonce_prefix);
        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(MAGIC);
        header[4] = 2;
        header[8..16].copy_from_slice(&ciphertext_len.to_be_bytes());
        output.write_all(&header)?;
        output.write_all(&[0u8; WRAP_RECORD_LEN + RECOVERY_RECORD_LEN])?;
        output.write_all(&envelope_header)?;
        let cipher = Aes256Gcm::new_from_slice(file_key.as_ref()).expect("fixed key length");
        let mut envelope_hash = Sha256::new();
        envelope_hash.update(envelope_header);
        let mut source_hash = Sha256::new();
        let mut plaintext = Zeroizing::new(vec![0u8; CHUNK_LEN]);
        for index in 0..chunks_for(plaintext_len) {
            let len = expected_chunk_len(plaintext_len, index);
            input.read_exact(&mut plaintext[..len])?;
            source_hash.update(&plaintext[..len]);
            let nonce = chunk_nonce(&envelope_header, index);
            let aad = chunk_aad(&envelope_header, index, len);
            let ciphertext = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &plaintext[..len],
                        aad: &aad,
                    },
                )
                .map_err(|_| auth_failed())?;
            envelope_hash.update(&ciphertext);
            output.write_all(&ciphertext)?;
            plaintext[..len].fill(0);
        }
        let mut extra = [0u8; 1];
        if input.read(&mut extra)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source changed during encryption",
            ));
        }
        let envelope_sha256: [u8; 32] = envelope_hash.finalize().into();
        let phone_wrap = key_wrap::wrap_for_phone(&file_key, &envelope_sha256, phone_public_sec1)
            .map_err(io::Error::other)?;
        let recovery_wrap = recovery::wrap_for_recovery(&file_key, &envelope_sha256, recovery_key)
            .map_err(io::Error::other)?;
        header[16..48].copy_from_slice(&envelope_sha256);
        output.seek(SeekFrom::Start(0))?;
        output.write_all(&header)?;
        output.write_all(&phone_wrap)?;
        output.write_all(&recovery_wrap)?;
        output.sync_all()?;
        drop(output);
        let meta = read_metadata(destination)?;
        let unwrapped = recovery::unwrap_with_recovery_key(
            &meta.recovery_wrap,
            &meta.envelope_sha256,
            recovery_key,
        )
        .map_err(io::Error::other)?;
        let mut verifier = HashWriter(Sha256::new());
        decrypt_to_writer(destination, &meta, &unwrapped, &mut verifier)?;
        let recovered_hash: [u8; 32] = verifier.0.finalize().into();
        let original_hash: [u8; 32] = source_hash.finalize().into();
        if recovered_hash != original_hash {
            return Err(auth_failed());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn decrypt_to_writer(
    source: &Path,
    expected: &Metadata,
    file_key: &[u8; KEY_LEN],
    output: &mut impl Write,
) -> io::Result<()> {
    let current = read_metadata(source)?;
    if current.identity != expected.identity || current.envelope_sha256 != expected.envelope_sha256
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encrypted file changed during opening",
        ));
    }
    if current.version == Version::Legacy {
        let mut bytes = Vec::new();
        File::open(source)?
            .take(package::MAX_PACKAGE_LEN as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > package::MAX_PACKAGE_LEN {
            return Err(too_large());
        }
        if Sha256::digest(&bytes).as_slice() != expected.identity {
            return Err(invalid());
        }
        let parsed = package::parse(&bytes).map_err(io::Error::other)?;
        let plaintext = open(parsed.envelope, file_key).map_err(io::Error::other)?;
        output.write_all(&plaintext)?;
        return Ok(());
    }
    let mut input = File::open(source)?;
    input.seek(SeekFrom::Start(ENVELOPE_START as u64))?;
    let mut envelope_header = [0u8; ENVELOPE_HEADER_LEN];
    input.read_exact(&mut envelope_header)?;
    let mut hasher = Sha256::new();
    hasher.update(envelope_header);
    let cipher = Aes256Gcm::new_from_slice(file_key).expect("fixed key length");
    let mut ciphertext = vec![0u8; CHUNK_LEN + TAG_LEN as usize];
    for index in 0..chunks_for(current.plaintext_len) {
        let len = expected_chunk_len(current.plaintext_len, index);
        input.read_exact(&mut ciphertext[..len + TAG_LEN as usize])?;
        hasher.update(&ciphertext[..len + TAG_LEN as usize]);
        let nonce = chunk_nonce(&envelope_header, index);
        let aad = chunk_aad(&envelope_header, index, len);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext[..len + TAG_LEN as usize],
                        aad: &aad,
                    },
                )
                .map_err(|_| auth_failed())?,
        );
        output.write_all(&plaintext)?;
    }
    let calculated: [u8; 32] = hasher.finalize().into();
    if calculated != expected.envelope_sha256
        || input.metadata()?.len() != (ENVELOPE_START as u64 + envelope_len(current.plaintext_len)?)
    {
        return Err(auth_failed());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;

    #[test]
    fn round_trip_above_old_limit_and_detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("source.pkp");
        let mut content = vec![0u8; 17 * 1024 * 1024 + 17];
        for (index, byte) in content.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        fs::write(&source, &content).unwrap();
        let phone = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let recovery_key = recovery::new_recovery_key().unwrap();
        seal_to_new_file(
            &source,
            &destination,
            &phone.public_key().to_sec1_bytes(),
            &recovery_key,
        )
        .unwrap();
        let meta = read_metadata(&destination).unwrap();
        assert_eq!(meta.version, Version::Streaming);
        let key = recovery::unwrap_with_recovery_key(
            &meta.recovery_wrap,
            &meta.envelope_sha256,
            &recovery_key,
        )
        .unwrap();
        let mut opened = Vec::new();
        decrypt_to_writer(&destination, &meta, &key, &mut opened).unwrap();
        assert_eq!(opened, content);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&destination)
            .unwrap();
        file.seek(SeekFrom::Start(
            (ENVELOPE_START + ENVELOPE_HEADER_LEN + CHUNK_LEN + 9) as u64,
        ))
        .unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Current(-1)).unwrap();
        file.write_all(&[byte[0] ^ 1]).unwrap();
        let mut output = Vec::new();
        assert!(decrypt_to_writer(&destination, &meta, &key, &mut output).is_err());
    }

    #[test]
    fn empty_file_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("empty");
        let destination = dir.path().join("empty.pkp");
        fs::write(&source, []).unwrap();
        let phone = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let recovery_key = recovery::new_recovery_key().unwrap();
        seal_to_new_file(
            &source,
            &destination,
            &phone.public_key().to_sec1_bytes(),
            &recovery_key,
        )
        .unwrap();
        let meta = read_metadata(&destination).unwrap();
        let key = recovery::unwrap_with_recovery_key(
            &meta.recovery_wrap,
            &meta.envelope_sha256,
            &recovery_key,
        )
        .unwrap();
        let mut opened = Vec::new();
        decrypt_to_writer(&destination, &meta, &key, &mut opened).unwrap();
        assert!(opened.is_empty());
        let file = OpenOptions::new().write(true).open(&destination).unwrap();
        file.set_len(file.metadata().unwrap().len() - 1).unwrap();
        assert!(read_metadata(&destination).is_err());
    }

    #[test]
    fn format_bounds_are_checked_without_allocating_a_large_file() {
        assert!(envelope_len(MAX_SOURCE_LEN).is_ok());
        assert!(envelope_len(MAX_SOURCE_LEN + 1).is_err());
    }
}
