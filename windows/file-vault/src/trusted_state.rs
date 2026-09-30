//! Read-only use of the existing, administrator-protected PhoneKey pairing.
//! File-vault code never modifies Windows sign-in trust or account state.

use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use p256::ecdsa::VerifyingKey;
use phonekey_protocol::types::DeviceId;
use serde::Deserialize;

const MAX_STATE_BYTES: u64 = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedPhoneRecord {
    version: u32,
    android_device_id_hex: String,
    public_key_sec1_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsIdentityRecord {
    version: u32,
    windows_device_id_hex: String,
}

pub struct TrustedState {
    pub windows_device_id: DeviceId,
    pub phone_device_id: DeviceId,
    pub phone_signing_public_sec1: [u8; 65],
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(invalid("PhoneKey trust state is too large"));
    }
    Ok(bytes)
}

fn decode_hex<const N: usize>(text: &str) -> io::Result<[u8; N]> {
    if text.len() != 2 * N {
        return Err(invalid("PhoneKey trust field has the wrong length"));
    }
    let mut bytes = [0u8; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        fn nibble(value: u8) -> Option<u8> {
            match value {
                b'0'..=b'9' => Some(value - b'0'),
                b'a'..=b'f' => Some(value - b'a' + 10),
                b'A'..=b'F' => Some(value - b'A' + 10),
                _ => None,
            }
        }
        let high = nibble(pair[0]).ok_or_else(|| invalid("invalid PhoneKey trust hexadecimal"))?;
        let low = nibble(pair[1]).ok_or_else(|| invalid("invalid PhoneKey trust hexadecimal"))?;
        bytes[index] = high << 4 | low;
    }
    Ok(bytes)
}

impl TrustedState {
    pub fn load_production() -> io::Result<Self> {
        let program_data = env::var_os("PROGRAMDATA")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "PROGRAMDATA is unavailable"))?;
        let directory = PathBuf::from(program_data).join("PhoneKeyFiles").join("trust");
        Self::load_at(&directory).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "PhoneKey Files pairing at {} is unavailable: {error}. Run the one-time PhoneKey Files setup or refresh its phone pairing",
                    directory.display()
                ),
            )
        })
    }

    pub fn load_at(directory: &Path) -> io::Result<Self> {
        let phone: TrustedPhoneRecord =
            serde_json::from_slice(&read_bounded(&directory.join("trusted_phone.json"))?)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let windows: WindowsIdentityRecord =
            serde_json::from_slice(&read_bounded(&directory.join("windows_identity.json"))?)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if phone.version != 1 || windows.version != 1 {
            return Err(invalid("unsupported PhoneKey trust state version"));
        }
        let phone_device_id = DeviceId(decode_hex(&phone.android_device_id_hex)?);
        let windows_device_id = DeviceId(decode_hex(&windows.windows_device_id_hex)?);
        if phone_device_id.0.iter().all(|byte| *byte == 0)
            || windows_device_id.0.iter().all(|byte| *byte == 0)
        {
            return Err(invalid("PhoneKey device identity is empty"));
        }
        let signing_public = decode_hex::<65>(&phone.public_key_sec1_hex)?;
        if signing_public[0] != 4 || VerifyingKey::from_sec1_bytes(&signing_public).is_err() {
            return Err(invalid("PhoneKey signing public key is invalid"));
        }
        Ok(Self {
            windows_device_id,
            phone_device_id,
            phone_signing_public_sec1: signing_public,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;

    #[test]
    fn reads_only_matching_versioned_pairing_state() {
        let dir = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes((&[8; 32]).into()).unwrap();
        let public = signing.verifying_key().to_sec1_point(false);
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        std::fs::write(
            dir.path().join("trusted_phone.json"),
            format!(
                "{{\"version\":1,\"android_device_id_hex\":\"{}\",\"public_key_sec1_hex\":\"{}\"}}",
                hex(&[1; 16]),
                hex(public.as_bytes()),
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("windows_identity.json"),
            format!(
                "{{\"version\":1,\"windows_device_id_hex\":\"{}\"}}",
                hex(&[2; 16]),
            ),
        )
        .unwrap();
        let trust = TrustedState::load_at(dir.path()).unwrap();
        assert_eq!(trust.phone_device_id, DeviceId([1; 16]));
        assert_eq!(trust.windows_device_id, DeviceId([2; 16]));
    }
}
