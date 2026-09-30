//! Legacy PKP1 in-memory format. New files use PKP2 streaming; this parser
//! remains for opening packages created before that upgrade.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::key_wrap::{self, WRAP_RECORD_LEN};
use crate::recovery::{self, RECOVERY_RECORD_LEN};
use crate::{KEY_LEN, MAX_PLAINTEXT_LEN, VaultError, new_file_key, open, seal};

const MAGIC: &[u8; 4] = b"PKP1";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 3 + 8;
const MIN_ENVELOPE_LEN: usize = 44;
const MAX_ENVELOPE_LEN: usize = MAX_PLAINTEXT_LEN + 44;
const PHONE_START: usize = HEADER_LEN;
const RECOVERY_START: usize = PHONE_START + WRAP_RECORD_LEN;
const ENVELOPE_START: usize = RECOVERY_START + RECOVERY_RECORD_LEN;
pub const MAX_PACKAGE_LEN: usize = ENVELOPE_START + MAX_ENVELOPE_LEN;

pub struct PackageView<'a> {
    pub phone_wrap: &'a [u8],
    pub recovery_wrap: &'a [u8],
    pub envelope: &'a [u8],
    pub envelope_sha256: [u8; 32],
}

pub fn parse(package: &[u8]) -> Result<PackageView<'_>, VaultError> {
    if package.len() < ENVELOPE_START + MIN_ENVELOPE_LEN
        || &package[..4] != MAGIC
        || package[4] != VERSION
        || package[5..8] != [0u8; 3]
    {
        return Err(VaultError::InvalidFormat);
    }
    let declared = u64::from_be_bytes(package[8..16].try_into().expect("fixed slice"));
    let length = usize::try_from(declared).map_err(|_| VaultError::TooLarge)?;
    if !(MIN_ENVELOPE_LEN..=MAX_ENVELOPE_LEN).contains(&length) {
        return Err(VaultError::TooLarge);
    }
    if package.len() != ENVELOPE_START + length {
        return Err(VaultError::InvalidFormat);
    }
    let envelope = &package[ENVELOPE_START..];
    let hash: [u8; 32] = Sha256::digest(envelope).into();
    Ok(PackageView {
        phone_wrap: &package[PHONE_START..RECOVERY_START],
        recovery_wrap: &package[RECOVERY_START..ENVELOPE_START],
        envelope,
        envelope_sha256: hash,
    })
}

pub fn seal_package(
    plaintext: &[u8],
    phone_public_sec1: &[u8],
    recovery_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>, VaultError> {
    let file_key = new_file_key()?;
    let envelope = seal(plaintext, &file_key)?;
    let hash: [u8; 32] = Sha256::digest(&envelope).into();
    let phone_wrap = key_wrap::wrap_for_phone(&file_key, &hash, phone_public_sec1)?;
    let recovery_wrap = recovery::wrap_for_recovery(&file_key, &hash, recovery_key)?;
    let mut package = Vec::with_capacity(ENVELOPE_START + envelope.len());
    package.extend_from_slice(MAGIC);
    package.push(VERSION);
    package.extend_from_slice(&[0u8; 3]);
    package.extend_from_slice(&(envelope.len() as u64).to_be_bytes());
    package.extend_from_slice(&phone_wrap);
    package.extend_from_slice(&recovery_wrap);
    package.extend_from_slice(&envelope);
    Ok(package)
}

/// Recovery is an explicit exceptional route, not the normal phone-approved
/// opening path. A production UI must require the recovery code each time.
pub fn open_with_recovery(
    package: &[u8],
    recovery_key: &[u8; KEY_LEN],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let parsed = parse(package)?;
    let file_key = recovery::unwrap_with_recovery_key(
        parsed.recovery_wrap,
        &parsed.envelope_sha256,
        recovery_key,
    )?;
    open(parsed.envelope, &file_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;

    #[test]
    fn package_round_trip_with_recovery_and_phone_wrap() {
        let phone = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let recovery_key = recovery::new_recovery_key().unwrap();
        let package = seal_package(
            b"dummy document",
            &phone.public_key().to_sec1_bytes(),
            &recovery_key,
        )
        .unwrap();
        let parsed = parse(&package).unwrap();
        assert_eq!(
            open_with_recovery(&package, &recovery_key)
                .unwrap()
                .as_slice(),
            b"dummy document"
        );
        let phone_file_key =
            key_wrap::unwrap_with_phone_secret(parsed.phone_wrap, &parsed.envelope_sha256, &phone)
                .unwrap();
        assert_eq!(
            open(parsed.envelope, &phone_file_key).unwrap().as_slice(),
            b"dummy document"
        );
    }

    #[test]
    fn package_rejects_truncation_trailing_data_and_tamper() {
        let phone = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let recovery_key = recovery::new_recovery_key().unwrap();
        let package =
            seal_package(b"dummy", &phone.public_key().to_sec1_bytes(), &recovery_key).unwrap();
        assert!(parse(&package[..package.len() - 1]).is_err());
        let mut extended = package.clone();
        extended.push(0);
        assert!(parse(&extended).is_err());
        let mut changed = package.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(open_with_recovery(&changed, &recovery_key).is_err());
        let mut changed_wrap = package.clone();
        changed_wrap[RECOVERY_START + 4] ^= 1;
        assert!(open_with_recovery(&changed_wrap, &recovery_key).is_err());
    }
}
