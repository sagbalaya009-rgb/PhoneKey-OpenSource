//! One file-opening attempt. The caller supplies the already authenticated
//! phone identity and signing key; transport and trust enrollment live outside
//! this crate. No Windows sign-in state is read or changed here.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use p256::SecretKey;
use phonekey_protocol::error::ProtocolError;
use phonekey_protocol::file_open::{FileOpenChallenge, FileOpenProof, FileOpenSession};
use phonekey_protocol::types::{DeviceId, Nonce, SessionId};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{VaultError, files, key_return, stream_package};

const FILE_OPEN_TTL_MS: u64 = 60_000;

#[derive(Debug, Error)]
pub enum FileOpenError {
    #[error("file I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("file approval failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("encrypted file failed authentication: {0}")]
    Vault(#[from] VaultError),
    #[error("encrypted file changed during approval")]
    FileChanged,
    #[error("operating system randomness unavailable")]
    RandomUnavailable,
    #[error("invalid file-opening clock")]
    InvalidClock,
}

fn random_bytes<const N: usize>() -> Result<[u8; N], FileOpenError> {
    let mut bytes = [0u8; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| FileOpenError::RandomUnavailable)?;
    Ok(bytes)
}

fn new_return_secret() -> Result<SecretKey, FileOpenError> {
    for _ in 0..16 {
        let bytes = Zeroizing::new(random_bytes::<32>()?);
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
    Err(FileOpenError::RandomUnavailable)
}

fn new_session_id() -> Result<SessionId, FileOpenError> {
    loop {
        let bytes = random_bytes::<16>()?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(SessionId(bytes));
        }
    }
}

/// A single, expiring opening of the exact package read at construction.
/// The signing key must come from independently verified phone trust state.
pub struct FileOpenAttempt {
    source: PathBuf,
    package_identity: [u8; 32],
    challenge_sha256: [u8; 32],
    challenge: FileOpenChallenge,
    session: FileOpenSession,
    return_secret: SecretKey,
}

impl FileOpenAttempt {
    pub fn begin(
        source: &Path,
        windows_device_id: DeviceId,
        phone_device_id: DeviceId,
        trusted_phone_signing_public_sec1: &[u8],
        now_ms: u64,
        started: Instant,
    ) -> Result<Self, FileOpenError> {
        let expires_at_ms = now_ms
            .checked_add(FILE_OPEN_TTL_MS)
            .ok_or(FileOpenError::InvalidClock)?;
        let parsed = stream_package::read_metadata(source)?;
        let return_secret = new_return_secret()?;
        let return_public_sec1 = return_secret.public_key().to_sec1_bytes();
        let challenge = FileOpenChallenge {
            windows_device_id,
            phone_device_id,
            session_id: new_session_id()?,
            nonce: Nonce(random_bytes()?),
            envelope_sha256: parsed.envelope_sha256,
            phone_wrap: parsed.phone_wrap,
            return_public_sec1: return_public_sec1.as_ref().try_into().expect("P-256 SEC1"),
            issued_at_ms: now_ms,
            expires_at_ms,
        };
        let challenge_sha256: [u8; 32] = Sha256::digest(challenge.transcript()?).into();
        let session = FileOpenSession::new(
            challenge.clone(),
            trusted_phone_signing_public_sec1.to_vec(),
            started,
        )?;
        Ok(Self {
            source: source.to_path_buf(),
            package_identity: parsed.identity,
            challenge_sha256,
            challenge,
            session,
            return_secret,
        })
    }

    pub fn challenge(&self) -> &FileOpenChallenge {
        &self.challenge
    }

    pub fn qr_payload(&self) -> Result<String, FileOpenError> {
        Ok(self.challenge.qr_payload()?)
    }

    /// Authenticate the phone proof and release one file key to this local
    /// opening. PKP2 ciphertext is authenticated as it is streamed to output.
    pub fn complete_key(
        &mut self,
        proof: &FileOpenProof,
        now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<(stream_package::Metadata, Zeroizing<[u8; crate::KEY_LEN]>), FileOpenError> {
        let parsed = stream_package::read_metadata(&self.source)?;
        if parsed.identity != self.package_identity {
            return Err(FileOpenError::FileChanged);
        }
        self.session
            .redeem(proof, &parsed.envelope_sha256, now_ms, monotonic_now)?;
        let file_key = key_return::open_on_laptop(
            &proof.encrypted_file_key,
            &self.challenge_sha256,
            &self.return_secret,
        )?;
        Ok((parsed, file_key))
    }

    /// Small-file compatibility API used by the in-memory text viewer.
    pub fn complete(
        &mut self,
        proof: &FileOpenProof,
        now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, FileOpenError> {
        let (metadata, file_key) = self.complete_key(proof, now_ms, monotonic_now)?;
        Ok(files::decrypt_package_to_memory(
            &self.source,
            &metadata,
            &file_key,
            crate::MAX_PLAINTEXT_LEN,
        )?)
    }
}
