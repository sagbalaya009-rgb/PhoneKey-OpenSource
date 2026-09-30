//! Normal file opening: read-only pairing lookup, fresh QR/BLE proof, and
//! plaintext returned only after the current package and pairing are checked.

use std::error::Error;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use phonekey_protocol::file_open::FileOpenProof;
use zeroize::Zeroizing;

use crate::approved_open::FileOpenAttempt;
use crate::file_ble::{self, FileBleProgress};
use crate::trusted_state::TrustedState;
use crate::{KEY_LEN, files, stream_package};

pub type LiveOpenError = Box<dyn Error + Send + Sync>;

fn now_ms() -> Result<u64, LiveOpenError> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

/// Every call creates a new, 60-second, one-use file challenge. A caller may
/// display the QR but cannot obtain plaintext until the paired phone returns
/// a matching signed proof over BLE. No plaintext is written to disk here.
pub fn authorize_with_phone(
    encrypted: &Path,
    show_qr: impl FnOnce(&str, u64) -> Result<(), LiveOpenError>,
    mut progress: impl FnMut(FileBleProgress) -> Result<(), LiveOpenError>,
) -> Result<(stream_package::Metadata, Zeroizing<[u8; KEY_LEN]>), LiveOpenError> {
    let trust = TrustedState::load_production()?;
    let started = Instant::now();
    let mut attempt = FileOpenAttempt::begin(
        encrypted,
        trust.windows_device_id,
        trust.phone_device_id,
        &trust.phone_signing_public_sec1,
        now_ms()?,
        started,
    )?;
    let challenge_bytes = attempt.challenge().encode()?;
    show_qr(&attempt.qr_payload()?, attempt.challenge().expires_at_ms)?;
    let stop = AtomicBool::new(false);
    let proof_bytes = file_ble::exchange_file(
        &challenge_bytes,
        attempt.challenge().expires_at_ms,
        &stop,
        || Ok(false),
        |stage| progress(stage),
    )?
    .ok_or("No phone proof arrived before the QR expired")?;
    let current_trust = TrustedState::load_production()?;
    if current_trust.windows_device_id != trust.windows_device_id
        || current_trust.phone_device_id != trust.phone_device_id
        || current_trust.phone_signing_public_sec1 != trust.phone_signing_public_sec1
    {
        return Err("PhoneKey pairing changed during this file opening".into());
    }
    let proof = FileOpenProof::decode(&proof_bytes)?;
    Ok(attempt.complete_key(&proof, now_ms()?, Instant::now())?)
}

/// The built-in viewer is intentionally limited to small UTF-8 text.
pub fn open_with_phone(
    encrypted: &Path,
    show_qr: impl FnOnce(&str, u64) -> Result<(), LiveOpenError>,
    progress: impl FnMut(FileBleProgress) -> Result<(), LiveOpenError>,
) -> Result<Zeroizing<Vec<u8>>, LiveOpenError> {
    if stream_package::read_metadata(encrypted)?.plaintext_len > 1024 * 1024 {
        return Err("This viewer accepts text up to 1 MiB; use explicit phone-approved export for other files".into());
    }
    let (metadata, file_key) = authorize_with_phone(encrypted, show_qr, progress)?;
    Ok(files::decrypt_package_to_memory(
        encrypted,
        &metadata,
        &file_key,
        1024 * 1024,
    )?)
}
