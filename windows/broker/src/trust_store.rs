use std::fs;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use phonekey_protocol::types::DeviceId;

const TRUST_STORE_VERSION: u32 = 1;
const P256_PUBLIC_KEY_LENGTH: usize = 65;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredTrustedPhone {
    version: u32,
    android_device_id_hex: String,
    public_key_sec1_hex: String,
}

#[derive(Debug, Clone)]
pub struct TrustedPhone {
    pub android_device_id: DeviceId,
    pub public_key_sec1: Vec<u8>,
}

pub fn trust_store_path() -> io::Result<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "LOCALAPPDATA is unavailable"))?;

    Ok(PathBuf::from(local_app_data)
        .join("PhoneKey")
        .join("trust")
        .join("trusted_phone.json"))
}

pub fn exists() -> io::Result<bool> {
    Ok(trust_store_path()?.is_file())
}

pub fn load() -> io::Result<TrustedPhone> {
    let path = trust_store_path()?;

    let data = fs::read_to_string(&path)?;

    let stored: StoredTrustedPhone = serde_json::from_str(&data).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid PhoneKey trust store: {error}"),
        )
    })?;

    if stored.version != TRUST_STORE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported trust store version {}", stored.version),
        ));
    }

    let device_id_bytes = decode_hex(&stored.android_device_id_hex)?;

    if device_id_bytes.len() != 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trusted Android device ID must be 16 bytes",
        ));
    }

    let mut device_id = [0u8; 16];

    device_id.copy_from_slice(&device_id_bytes);

    let public_key = decode_hex(&stored.public_key_sec1_hex)?;

    if public_key.len() != P256_PUBLIC_KEY_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trusted P-256 public key must be 65 bytes",
        ));
    }

    if public_key[0] != 0x04 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trusted P-256 public key must use uncompressed SEC1 encoding",
        ));
    }

    Ok(TrustedPhone {
        android_device_id: DeviceId(device_id),
        public_key_sec1: public_key,
    })
}

pub fn revoke() -> io::Result<bool> {
    let path = trust_store_path()?;

    if !path.exists() {
        return Ok(false);
    }

    fs::remove_file(path)?;

    Ok(true)
}

fn decode_hex(value: &str) -> io::Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hex value has invalid length",
        ));
    }

    let mut output = Vec::with_capacity(value.len() / 2);

    for index in (0..value.len()).step_by(2) {
        let byte = u8::from_str_radix(&value[index..index + 2], 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Trust store contains invalid hex",
            )
        })?;

        output.push(byte);
    }

    Ok(output)
}
