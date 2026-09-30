use phonekey_protocol::types::DeviceId;

use p256::ecdsa::VerifyingKey;

use serde::{Deserialize, Serialize};

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const TRUST_STATE_VERSION: u32 = 1;
const DEVICE_ID_LENGTH: usize = 16;
const P256_PUBLIC_KEY_LENGTH: usize = 65;

pub struct TrustedPhone {
    pub android_device_id: DeviceId,
    pub public_key_sec1: [u8; P256_PUBLIC_KEY_LENGTH],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedPhoneRecord {
    version: u32,
    android_device_id_hex: String,
    public_key_sec1_hex: String,
}

pub fn trusted_phone_path() -> io::Result<PathBuf> {
    let program_data = env::var_os("PROGRAMDATA")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "PROGRAMDATA is unavailable"))?;

    Ok(PathBuf::from(program_data)
        .join("PhoneKey")
        .join("state")
        .join("trusted_phone.json"))
}

pub fn validate_production_store() -> io::Result<bool> {
    let path = trusted_phone_path()?;

    Ok(load_at(&path)?.is_some())
}

pub fn load_production() -> io::Result<Option<TrustedPhone>> {
    let path = trusted_phone_path()?;

    load_at(&path)
}

pub fn enroll_production(trusted_phone: &TrustedPhone) -> io::Result<()> {
    let path = trusted_phone_path()?;

    enroll_production_at(&path, trusted_phone)
}

fn enroll_production_at(path: &Path, trusted_phone: &TrustedPhone) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted phone path has no parent",
        )
    })?;

    /*
     * Production must never recreate the protected PhoneKey
     * state directory with ordinary inherited permissions.
     *
     * Installation owns creation and ACL hardening of:
     *
     *     %PROGRAMDATA%\PhoneKey\state
     *
     * If that directory disappears, enrollment fails closed.
     *
     * enroll_at() intentionally retains its generic
     * create-directory behavior for isolated tests and
     * non-production callers.
     */
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "protected PhoneKey state directory is missing",
        ));
    }

    enroll_at(path, trusted_phone)
}

pub fn load_at(path: &Path) -> io::Result<Option<TrustedPhone>> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(path)?;

    let record: TrustedPhoneRecord = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid PhoneKey trust JSON: {error}"),
        )
    })?;

    let trusted_phone = record_to_trusted_phone(&record)?;

    Ok(Some(trusted_phone))
}

pub fn enroll_at(path: &Path, trusted_phone: &TrustedPhone) -> io::Result<()> {
    validate_trusted_phone(trusted_phone)?;

    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a privileged PhoneKey enrollment already exists",
        ));
    }

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted phone path has no parent",
        )
    })?;

    fs::create_dir_all(parent)?;

    let record = TrustedPhoneRecord {
        version: TRUST_STATE_VERSION,

        android_device_id_hex: encode_hex(&trusted_phone.android_device_id.0),

        public_key_sec1_hex: encode_hex(&trusted_phone.public_key_sec1),
    };

    let mut bytes = serde_json::to_vec_pretty(&record).map_err(io::Error::other)?;

    bytes.push(b'\n');

    let temporary_path = temporary_path(parent);

    let write_result = write_new_file(&temporary_path, &bytes);

    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);

        return Err(error);
    }

    match fs::rename(&temporary_path, path) {
        Ok(()) => {}

        Err(error) => {
            let _ = fs::remove_file(&temporary_path);

            return Err(error);
        }
    }

    /*
     * Never trust our own serialization blindly.
     * Re-open and validate exactly what was persisted.
     */
    let persisted = load_at(path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "trusted phone disappeared immediately after enrollment",
        )
    })?;

    if persisted.android_device_id != trusted_phone.android_device_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "persisted Android device identity mismatch",
        ));
    }

    if persisted.public_key_sec1 != trusted_phone.public_key_sec1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "persisted phone public key mismatch",
        ));
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
    use rand::RngCore as _;

    let mut random = [0u8; 8];

    rand::rng().fill_bytes(&mut random);

    parent.join(format!(
        ".trusted_phone.{}.{}.tmp",
        std::process::id(),
        encode_hex(&random),
    ))
}

fn record_to_trusted_phone(record: &TrustedPhoneRecord) -> io::Result<TrustedPhone> {
    if record.version != TRUST_STATE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported PhoneKey trust state version",
        ));
    }

    let android_device_id =
        decode_hex_exact::<DEVICE_ID_LENGTH>(&record.android_device_id_hex, "Android device ID")?;

    let public_key_sec1 = decode_hex_exact::<P256_PUBLIC_KEY_LENGTH>(
        &record.public_key_sec1_hex,
        "P-256 public key",
    )?;

    let trusted_phone = TrustedPhone {
        android_device_id: DeviceId(android_device_id),

        public_key_sec1,
    };

    validate_trusted_phone(&trusted_phone)?;

    Ok(trusted_phone)
}

fn validate_trusted_phone(trusted_phone: &TrustedPhone) -> io::Result<()> {
    if trusted_phone
        .android_device_id
        .0
        .iter()
        .all(|value| *value == 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "all-zero Android device ID is forbidden",
        ));
    }

    if trusted_phone.public_key_sec1[0] != 0x04 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PhoneKey requires an uncompressed SEC1 P-256 public key",
        ));
    }

    VerifyingKey::from_sec1_bytes(&trusted_phone.public_key_sec1).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "trusted phone contains an invalid P-256 public key",
        )
    })?;

    Ok(())
}

fn encode_hex(value: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(value.len() * 2);

    for byte in value {
        write!(&mut output, "{byte:02x}").expect("writing hexadecimal to String cannot fail");
    }

    output
}

fn decode_hex_exact<const N: usize>(value: &str, field_name: &str) -> io::Result<[u8; N]> {
    if value.len() != N * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field_name} has the wrong length"),
        ));
    }

    if !value.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field_name} must be ASCII hexadecimal"),
        ));
    }

    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field_name} must use canonical lowercase hexadecimal"),
        ));
    }

    let mut output = [0u8; N];

    for (index, destination) in output.iter_mut().enumerate() {
        let start = index * 2;

        *destination = u8::from_str_radix(&value[start..start + 2], 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{field_name} contains invalid hexadecimal"),
            )
        })?;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    use p256::ecdsa::SigningKey;

    use tempfile::tempdir;

    fn valid_phone() -> TrustedPhone {
        let signing_key = SigningKey::from_slice(&[0x01; 32]).unwrap();

        let point = signing_key.verifying_key().to_sec1_point(false);

        let mut public_key = [0u8; P256_PUBLIC_KEY_LENGTH];

        public_key.copy_from_slice(point.as_bytes());

        TrustedPhone {
            android_device_id: DeviceId([0x22; DEVICE_ID_LENGTH]),

            public_key_sec1: public_key,
        }
    }

    #[test]
    fn missing_store_returns_none() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        assert!(load_at(&path).unwrap().is_none());
    }

    #[test]
    fn trusted_phone_round_trips() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let phone = valid_phone();

        enroll_at(&path, &phone).unwrap();

        let loaded = load_at(&path).unwrap().unwrap();

        assert_eq!(loaded.android_device_id, phone.android_device_id);

        assert_eq!(loaded.public_key_sec1, phone.public_key_sec1);
    }

    #[test]
    fn existing_enrollment_is_not_overwritten() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let phone = valid_phone();

        enroll_at(&path, &phone).unwrap();

        let result = enroll_at(&path, &phone);

        assert!(result.is_err());
    }

    #[test]
    fn all_zero_device_id_is_rejected() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let mut phone = valid_phone();

        phone.android_device_id = DeviceId([0u8; DEVICE_ID_LENGTH]);

        assert!(enroll_at(&path, &phone).is_err());
    }

    #[test]
    fn invalid_public_key_is_rejected() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let mut phone = valid_phone();

        phone.public_key_sec1 = [0u8; P256_PUBLIC_KEY_LENGTH];

        phone.public_key_sec1[0] = 0x04;

        assert!(enroll_at(&path, &phone).is_err());
    }

    #[test]
    fn unknown_json_fields_fail_closed() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let phone = valid_phone();

        let json = format!(
            concat!(
                "{{",
                "\"version\":1,",
                "\"android_device_id_hex\":\"{}\",",
                "\"public_key_sec1_hex\":\"{}\",",
                "\"attacker_field\":\"unexpected\"",
                "}}"
            ),
            encode_hex(&phone.android_device_id.0),
            encode_hex(&phone.public_key_sec1),
        );

        fs::write(&path, json).unwrap();

        assert!(load_at(&path).is_err());
    }

    #[test]
    fn uppercase_hex_fails_closed() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let phone = valid_phone();

        let json = format!(
            concat!(
                "{{",
                "\"version\":1,",
                "\"android_device_id_hex\":",
                "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",",
                "\"public_key_sec1_hex\":\"{}\"",
                "}}"
            ),
            encode_hex(&phone.public_key_sec1),
        );

        fs::write(&path, json).unwrap();

        assert!(load_at(&path).is_err());
    }

    #[test]
    fn wrong_state_version_fails_closed() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let phone = valid_phone();

        let json = format!(
            concat!(
                "{{",
                "\"version\":2,",
                "\"android_device_id_hex\":\"{}\",",
                "\"public_key_sec1_hex\":\"{}\"",
                "}}"
            ),
            encode_hex(&phone.android_device_id.0),
            encode_hex(&phone.public_key_sec1),
        );

        fs::write(&path, json).unwrap();

        assert!(load_at(&path).is_err());
    }

    #[test]
    fn malformed_device_id_fails_closed() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let phone = valid_phone();

        let json = format!(
            concat!(
                "{{",
                "\"version\":1,",
                "\"android_device_id_hex\":",
                "\"gggggggggggggggggggggggggggggggg\",",
                "\"public_key_sec1_hex\":\"{}\"",
                "}}"
            ),
            encode_hex(&phone.public_key_sec1),
        );

        fs::write(&path, json).unwrap();

        assert!(load_at(&path).is_err());
    }

    #[test]
    fn compressed_public_key_fails_closed() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        let phone = valid_phone();

        let signing_key = SigningKey::from_slice(&[0x01; 32]).unwrap();

        let compressed = signing_key.verifying_key().to_sec1_point(true);

        let json = format!(
            concat!(
                "{{",
                "\"version\":1,",
                "\"android_device_id_hex\":\"{}\",",
                "\"public_key_sec1_hex\":\"{}\"",
                "}}"
            ),
            encode_hex(&phone.android_device_id.0),
            encode_hex(compressed.as_bytes()),
        );

        fs::write(&path, json).unwrap();

        assert!(load_at(&path).is_err());
    }

    #[test]
    fn corrupt_json_fails_closed() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("trusted_phone.json");

        fs::write(&path, b"{ this is not valid PhoneKey JSON").unwrap();

        assert!(load_at(&path).is_err());
    }
}
#[cfg(test)]
mod production_path_tests {
    use super::*;

    use p256::ecdsa::SigningKey;
    use tempfile::tempdir;

    fn valid_phone() -> TrustedPhone {
        let signing_key = SigningKey::from_slice(&[0x01; 32]).unwrap();

        let encoded_point = signing_key.verifying_key().to_sec1_point(false);

        let mut public_key_sec1 = [0u8; P256_PUBLIC_KEY_LENGTH];

        public_key_sec1.copy_from_slice(encoded_point.as_bytes());

        TrustedPhone {
            android_device_id: DeviceId([0x22; DEVICE_ID_LENGTH]),
            public_key_sec1,
        }
    }

    #[test]
    fn production_enrollment_refuses_to_create_missing_protected_parent() {
        let directory = tempdir().unwrap();

        let missing_parent = directory.path().join("PhoneKey").join("state");

        let trust_path = missing_parent.join("trusted_phone.json");

        assert!(!missing_parent.exists());

        let result = enroll_production_at(&trust_path, &valid_phone());

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound,);

        assert!(!missing_parent.exists());
        assert!(!trust_path.exists());
    }

    #[test]
    fn production_enrollment_uses_existing_protected_parent() {
        let directory = tempdir().unwrap();

        let existing_parent = directory.path().join("PhoneKey").join("state");

        fs::create_dir_all(&existing_parent).unwrap();

        let trust_path = existing_parent.join("trusted_phone.json");

        let phone = valid_phone();

        enroll_production_at(&trust_path, &phone).unwrap();

        let persisted = load_at(&trust_path).unwrap().unwrap();

        assert_eq!(persisted.android_device_id, phone.android_device_id,);

        assert_eq!(persisted.public_key_sec1, phone.public_key_sec1,);
    }

    #[test]
    fn production_enrollment_remains_create_only() {
        let directory = tempdir().unwrap();

        let existing_parent = directory.path().join("PhoneKey").join("state");

        fs::create_dir_all(&existing_parent).unwrap();

        let trust_path = existing_parent.join("trusted_phone.json");

        let phone = valid_phone();

        enroll_production_at(&trust_path, &phone).unwrap();

        let duplicate = enroll_production_at(&trust_path, &phone);

        assert_eq!(duplicate.unwrap_err().kind(), io::ErrorKind::AlreadyExists,);
    }
}
