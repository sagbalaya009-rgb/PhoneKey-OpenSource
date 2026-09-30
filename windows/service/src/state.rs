use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const STATE_VERSION: u32 = 1;
const DEVICE_ID_LENGTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsIdentity {
    pub device_id: [u8; DEVICE_ID_LENGTH],
}

#[derive(Debug, Serialize, Deserialize)]
struct WindowsIdentityRecord {
    version: u32,

    windows_device_id_hex: String,
}

pub fn windows_identity_path() -> io::Result<PathBuf> {
    let program_data = env::var_os("PROGRAMDATA")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "PROGRAMDATA is unavailable"))?;

    Ok(PathBuf::from(program_data)
        .join("PhoneKey")
        .join("state")
        .join("windows_identity.json"))
}

pub fn load_or_create_windows_identity() -> io::Result<WindowsIdentity> {
    let path = windows_identity_path()?;
    if !path.parent().is_some_and(Path::is_dir) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "installer must create the protected state directory before service startup",
        ));
    }
    load_or_create_at(&path)
}

pub fn load_or_create_at(path: &Path) -> io::Result<WindowsIdentity> {
    if path.exists() {
        return load_at(path);
    }

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "identity path has no parent")
    })?;

    fs::create_dir_all(parent)?;

    let device_id = generate_device_id();

    let record = WindowsIdentityRecord {
        version: STATE_VERSION,

        windows_device_id_hex: encode_hex(&device_id),
    };

    let mut serialized = serde_json::to_vec_pretty(&record).map_err(io::Error::other)?;

    serialized.push(b'\n');

    let temporary_path = temporary_path(parent);

    let mut temporary_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)?;

    temporary_file.write_all(&serialized)?;

    temporary_file.sync_all()?;

    drop(temporary_file);

    match fs::rename(&temporary_path, path) {
        Ok(()) => load_at(path),

        Err(error) => {
            let _ = fs::remove_file(&temporary_path);

            /*
             * Another PhoneKey service instance
             * may have won the creation race.
             *
             * Never overwrite an established
             * Windows identity.
             */
            if path.exists() {
                load_at(path)
            } else {
                Err(error)
            }
        }
    }
}

fn load_at(path: &Path) -> io::Result<WindowsIdentity> {
    let bytes = fs::read(path)?;

    let record: WindowsIdentityRecord = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    if record.version != STATE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported Windows identity state version",
        ));
    }

    let device_id = decode_device_id(&record.windows_device_id_hex)?;

    Ok(WindowsIdentity { device_id })
}

fn generate_device_id() -> [u8; DEVICE_ID_LENGTH] {
    loop {
        let mut bytes = [0u8; DEVICE_ID_LENGTH];

        rand::rng().fill_bytes(&mut bytes);

        if bytes.iter().any(|value| *value != 0) {
            return bytes;
        }
    }
}

fn temporary_path(parent: &Path) -> PathBuf {
    let mut random = [0u8; 8];

    rand::rng().fill_bytes(&mut random);

    parent.join(format!(
        ".windows_identity.{}.{}.tmp",
        std::process::id(),
        encode_hex(&random)
    ))
}

fn encode_hex(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);

    for byte in value {
        use std::fmt::Write as _;

        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }

    output
}

fn decode_device_id(value: &str) -> io::Result<[u8; DEVICE_ID_LENGTH]> {
    if value.len() != DEVICE_ID_LENGTH * 2 || !value.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Windows device ID length",
        ));
    }

    let mut output = [0u8; DEVICE_ID_LENGTH];

    for (index, output_byte) in output.iter_mut().enumerate() {
        let start = index * 2;

        *output_byte = u8::from_str_radix(&value[start..start + 2], 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows device ID contains invalid hex",
            )
        })?;
    }

    if output.iter().all(|value| *value == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "all-zero Windows device ID is forbidden",
        ));
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn identity_is_created_and_stable() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("windows_identity.json");

        let first = load_or_create_at(&path).unwrap();

        let second = load_or_create_at(&path).unwrap();

        assert_eq!(first, second);

        assert!(first.device_id.iter().any(|value| *value != 0));
    }

    #[test]
    fn wrong_state_version_is_rejected() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("windows_identity.json");

        fs::write(
            &path,
            r#"{
                "version": 999,
                "windows_device_id_hex": "11111111111111111111111111111111"
            }"#,
        )
        .unwrap();

        assert!(load_or_create_at(&path).is_err());
    }

    #[test]
    fn malformed_device_id_is_rejected() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("windows_identity.json");

        fs::write(
            &path,
            r#"{
                "version": 1,
                "windows_device_id_hex": "not-a-device-id"
            }"#,
        )
        .unwrap();

        assert!(load_or_create_at(&path).is_err());
    }

    #[test]
    fn all_zero_device_id_is_rejected() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("windows_identity.json");

        fs::write(
            &path,
            r#"{
                "version": 1,
                "windows_device_id_hex": "00000000000000000000000000000000"
            }"#,
        )
        .unwrap();

        assert!(load_or_create_at(&path).is_err());
    }

    #[test]
    fn corrupt_json_is_rejected() {
        let directory = tempdir().unwrap();

        let path = directory.path().join("windows_identity.json");

        fs::write(&path, b"{ definitely not valid json").unwrap();

        assert!(load_or_create_at(&path).is_err());
    }
}
