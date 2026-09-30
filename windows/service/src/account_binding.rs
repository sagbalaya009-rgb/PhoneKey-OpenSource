use crate::trust_store;

use phonekey_protocol::types::DeviceId;

use rand::RngCore as _;

use serde::{Deserialize, Serialize};

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

const ACCOUNT_BINDING_VERSION: u32 = 1;
const DEVICE_ID_LENGTH: usize = 16;
const MAX_WINDOWS_SID_LENGTH: usize = 184;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedAccount {
    pub windows_sid: String,
    pub android_device_id: DeviceId,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizedAccountRecord {
    version: u32,
    windows_sid: String,
    android_device_id_hex: String,
}

#[derive(Debug, Error)]
pub enum AccountBindingError {
    #[error("Windows SID is invalid")]
    InvalidSid,

    #[error("no privileged PhoneKey enrollment exists")]
    NoTrustedPhone,

    #[error("a Windows account is already permanently authorized")]
    AlreadyBound,

    #[error("PhoneKey account-binding state failed: {0}")]
    Io(#[from] io::Error),
}

pub fn authorized_account_path() -> io::Result<PathBuf> {
    let program_data = env::var_os("PROGRAMDATA")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "PROGRAMDATA is unavailable"))?;

    Ok(PathBuf::from(program_data)
        .join("PhoneKey")
        .join("state")
        .join("authorized_account.json"))
}

pub fn validate_production_store() -> Result<bool, AccountBindingError> {
    let path = authorized_account_path()?;

    Ok(load_at(&path)?.is_some())
}

pub fn load_production() -> Result<Option<AuthorizedAccount>, AccountBindingError> {
    let path = authorized_account_path()?;

    load_at(&path)
}

pub fn bind_production(windows_sid: &str) -> Result<(), AccountBindingError> {
    validate_windows_sid(windows_sid)?;

    let trusted_phone =
        trust_store::load_production()?.ok_or(AccountBindingError::NoTrustedPhone)?;

    let path = authorized_account_path()?;

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "authorized-account path has no parent",
        )
    })?;

    /*
     * Production must never create a replacement state
     * directory with default permissions.
     *
     * The protected PhoneKey state directory must already
     * exist because machine identity and phone trust live
     * there.
     */
    if !parent.is_dir() {
        return Err(AccountBindingError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "protected PhoneKey state directory is missing",
        )));
    }

    bind_at(&path, windows_sid, trusted_phone.android_device_id)
}

pub fn load_at(path: &Path) -> Result<Option<AuthorizedAccount>, AccountBindingError> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(path)?;

    let record: AuthorizedAccountRecord = serde_json::from_slice(&bytes).map_err(|error| {
        AccountBindingError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid PhoneKey account-binding JSON: {error}"),
        ))
    })?;

    if record.version != ACCOUNT_BINDING_VERSION {
        return Err(AccountBindingError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported PhoneKey account-binding version",
        )));
    }

    validate_windows_sid(&record.windows_sid)?;

    let android_device_id =
        decode_hex_exact::<DEVICE_ID_LENGTH>(&record.android_device_id_hex, "Android device ID")?;

    if android_device_id.iter().all(|byte| *byte == 0) {
        return Err(AccountBindingError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "account binding contains an all-zero Android device ID",
        )));
    }

    Ok(Some(AuthorizedAccount {
        windows_sid: record.windows_sid,

        android_device_id: DeviceId(android_device_id),
    }))
}

pub fn bind_at(
    path: &Path,
    windows_sid: &str,
    android_device_id: DeviceId,
) -> Result<(), AccountBindingError> {
    validate_windows_sid(windows_sid)?;

    if android_device_id.0.iter().all(|byte| *byte == 0) {
        return Err(AccountBindingError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "all-zero Android device ID is forbidden",
        )));
    }

    if path.exists() {
        return Err(AccountBindingError::AlreadyBound);
    }

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "authorized-account path has no parent",
        )
    })?;

    fs::create_dir_all(parent)?;

    let record = AuthorizedAccountRecord {
        version: ACCOUNT_BINDING_VERSION,

        windows_sid: windows_sid.to_owned(),

        android_device_id_hex: encode_hex(&android_device_id.0),
    };

    let mut bytes = serde_json::to_vec_pretty(&record).map_err(io::Error::other)?;

    bytes.push(b'\n');

    let temporary_path = temporary_path(parent);

    if let Err(error) = write_new_file(&temporary_path, &bytes) {
        let _ = fs::remove_file(&temporary_path);

        return Err(AccountBindingError::Io(error));
    }

    match fs::rename(&temporary_path, path) {
        Ok(()) => {}

        Err(error) => {
            let _ = fs::remove_file(&temporary_path);

            return Err(AccountBindingError::Io(error));
        }
    }

    let persisted = load_at(path)?.ok_or_else(|| {
        AccountBindingError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "authorized account disappeared after persistence",
        ))
    })?;

    if persisted.windows_sid != windows_sid {
        return Err(AccountBindingError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "persisted Windows SID mismatch",
        )));
    }

    if persisted.android_device_id != android_device_id {
        return Err(AccountBindingError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "persisted Android identity mismatch",
        )));
    }

    Ok(())
}

pub fn validate_windows_sid(sid: &str) -> Result<(), AccountBindingError> {
    if sid.is_empty() || sid.len() > MAX_WINDOWS_SID_LENGTH || !sid.is_ascii() {
        return Err(AccountBindingError::InvalidSid);
    }

    let components: Vec<&str> = sid.split('-').collect();

    /*
     * Canonical Windows SID strings returned by
     * ConvertSidToStringSidW begin with:
     *
     * S-1-<identifier-authority>-...
     */
    if components.len() < 4 || components[0] != "S" || components[1] != "1" {
        return Err(AccountBindingError::InvalidSid);
    }

    if components[2..].iter().any(|component| {
        component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return Err(AccountBindingError::InvalidSid);
    }

    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;

    file.write_all(bytes)?;

    file.sync_all()?;

    Ok(())
}

fn temporary_path(parent: &Path) -> PathBuf {
    let mut random = [0u8; 8];

    rand::rng().fill_bytes(&mut random);

    parent.join(format!(
        ".authorized_account.{}.{}.tmp",
        std::process::id(),
        encode_hex(&random),
    ))
}

fn encode_hex(value: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(value.len() * 2);

    for byte in value {
        write!(&mut output, "{byte:02x}").expect("writing hexadecimal to String cannot fail");
    }

    output
}

fn decode_hex_exact<const N: usize>(
    value: &str,
    field_name: &str,
) -> Result<[u8; N], AccountBindingError> {
    if value.len() != N * 2 {
        return Err(AccountBindingError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field_name} has the wrong length"),
        )));
    }

    if !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AccountBindingError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field_name} must use canonical lowercase hexadecimal"),
        )));
    }

    let mut output = [0u8; N];

    for (index, destination) in output.iter_mut().enumerate() {
        let start = index * 2;

        *destination = u8::from_str_radix(&value[start..start + 2], 16).map_err(|_| {
            AccountBindingError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{field_name} contains invalid hexadecimal"),
            ))
        })?;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::tempdir;

    const SID_A: &str = "S-1-5-21-111111111-222222222-333333333-1001";

    const ANDROID_ID: DeviceId = DeviceId([0x44; 16]);

    #[test]
    fn missing_store_returns_none() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("authorized_account.json");

        assert!(load_at(&path).unwrap().is_none());
    }

    #[test]
    fn binding_round_trips() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("authorized_account.json");

        bind_at(&path, SID_A, ANDROID_ID).unwrap();

        let loaded = load_at(&path).unwrap().unwrap();

        assert_eq!(loaded.windows_sid, SID_A);

        assert_eq!(loaded.android_device_id, ANDROID_ID);
    }

    #[test]
    fn binding_is_create_only() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("authorized_account.json");

        bind_at(&path, SID_A, ANDROID_ID).unwrap();

        assert!(matches!(
            bind_at(&path, SID_A, ANDROID_ID,),
            Err(AccountBindingError::AlreadyBound)
        ));
    }

    #[test]
    fn malformed_sid_is_rejected() {
        assert!(matches!(
            validate_windows_sid("not-a-sid"),
            Err(AccountBindingError::InvalidSid)
        ));

        assert!(matches!(
            validate_windows_sid("S-2-5-21-123"),
            Err(AccountBindingError::InvalidSid)
        ));
    }

    #[test]
    fn all_zero_phone_id_is_rejected() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("authorized_account.json");

        assert!(bind_at(&path, SID_A, DeviceId([0u8; 16]),).is_err());
    }

    #[test]
    fn unknown_json_fields_fail_closed() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("authorized_account.json");

        let json = concat!(
            "{",
            "\"version\":1,",
            "\"windows_sid\":\"S-1-5-21-1-2-3-1001\",",
            "\"android_device_id_hex\":\"44444444444444444444444444444444\",",
            "\"attacker_field\":true",
            "}"
        );

        fs::write(&path, json).unwrap();

        assert!(load_at(&path).is_err());
    }

    #[test]
    fn uppercase_phone_id_fails_closed() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("authorized_account.json");

        let json = concat!(
            "{",
            "\"version\":1,",
            "\"windows_sid\":\"S-1-5-21-1-2-3-1001\",",
            "\"android_device_id_hex\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
            "}"
        );

        fs::write(&path, json).unwrap();

        assert!(load_at(&path).is_err());
    }
}
