//! Human-copyable form of the random 256-bit lost-phone recovery key.
//! It is not a password and must be stored separately from encrypted files.

use thiserror::Error;
use zeroize::Zeroizing;

use crate::KEY_LEN;

const PREFIX: &str = "PKRC1-";
const GROUPS: usize = 8;
const GROUP_HEX_LEN: usize = 8;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid PhoneKey recovery code")]
pub struct InvalidRecoveryCode;

pub fn format(key: &[u8; KEY_LEN]) -> Zeroizing<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = Zeroizing::new(String::with_capacity(PREFIX.len() + 64 + GROUPS - 1));
    value.push_str(PREFIX);
    for (index, byte) in key.iter().enumerate() {
        if index > 0 && index % 4 == 0 {
            value.push('-');
        }
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 15) as usize] as char);
    }
    value
}

pub fn parse(value: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, InvalidRecoveryCode> {
    if value.len() != PREFIX.len() + 64 + GROUPS - 1 || !value.starts_with(PREFIX) {
        return Err(InvalidRecoveryCode);
    }
    let groups: Vec<&str> = value[PREFIX.len()..].split('-').collect();
    if groups.len() != GROUPS || groups.iter().any(|group| group.len() != GROUP_HEX_LEN) {
        return Err(InvalidRecoveryCode);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    for (group_index, group) in groups.iter().enumerate() {
        for (byte_index, pair) in group.as_bytes().chunks_exact(2).enumerate() {
            fn nibble(value: u8) -> Option<u8> {
                match value {
                    b'0'..=b'9' => Some(value - b'0'),
                    b'a'..=b'f' => Some(value - b'a' + 10),
                    _ => None,
                }
            }
            let high = nibble(pair[0]).ok_or(InvalidRecoveryCode)?;
            let low = nibble(pair[1]).ok_or(InvalidRecoveryCode)?;
            key[group_index * 4 + byte_index] = high << 4 | low;
        }
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::new_recovery_key;

    #[test]
    fn exact_recovery_code_round_trips_and_rejects_mistakes() {
        let key = new_recovery_key().unwrap();
        let value = format(&key);
        assert_eq!(*parse(&value).unwrap(), *key);
        let mut changed = value.to_string();
        changed.replace_range(10..11, "z");
        assert_eq!(parse(&changed), Err(InvalidRecoveryCode));
        assert_eq!(parse(&value.to_uppercase()), Err(InvalidRecoveryCode));
        assert_eq!(parse(&value[..value.len() - 1]), Err(InvalidRecoveryCode));
    }
}
