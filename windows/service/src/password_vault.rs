//! Service-account DPAPI vault for the one bound Windows account.
//! Never use CRYPTPROTECT_LOCAL_MACHINE: that would let other local users decrypt it.
use rand::RngCore as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::core::w;

const MAGIC: &[u8; 4] = b"PKV1";
const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_SID_BYTES: usize = 184;
const MAX_CIPHER_BYTES: usize = 8192;

pub struct RecoveredPassword {
    pub utf16: Vec<u16>,
}

impl Drop for RecoveredPassword {
    fn drop(&mut self) {
        self.utf16.fill(0);
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn protect(bytes: &mut [u8]) -> io::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let result = unsafe {
        CryptProtectData(
            &input,
            w!("PhoneKey Windows credential"),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    bytes.fill(0);
    result.map_err(io::Error::other)?;
    if output.pbData.is_null() || output.cbData == 0 || output.cbData as usize > MAX_CIPHER_BYTES {
        if !output.pbData.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
            }
        }
        return Err(invalid("vault ciphertext too large"));
    }
    let ciphertext =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
    }
    Ok(ciphertext)
}

fn unprotect(ciphertext: &mut [u8]) -> io::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(io::Error::other)?;
    if output.pbData.is_null()
        || output.cbData == 0
        || output.cbData as usize > MAX_PASSWORD_BYTES + MAX_SID_BYTES + 4
    {
        if !output.pbData.is_null() {
            unsafe {
                std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
                let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
            }
        }
        return Err(invalid("vault plaintext length invalid"));
    }
    let plaintext =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
    }
    Ok(plaintext)
}

pub fn seal(sid: &str, password: &[u16]) -> io::Result<Vec<u8>> {
    if !sid.starts_with("S-1-")
        || !sid.is_ascii()
        || sid.len() > MAX_SID_BYTES
        || password.is_empty()
        || password.len() * 2 > MAX_PASSWORD_BYTES
        || password.contains(&0)
        || std::char::decode_utf16(password.iter().copied()).any(|unit| unit.is_err())
    {
        return Err(invalid("invalid vault account or password"));
    }
    let mut plaintext = Vec::with_capacity(4 + sid.len() + password.len() * 2);
    plaintext.extend_from_slice(&(sid.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(sid.as_bytes());
    plaintext.extend_from_slice(&(password.len() as u16).to_be_bytes());
    for unit in password {
        plaintext.extend_from_slice(&unit.to_le_bytes());
    }
    let ciphertext = protect(&mut plaintext)?;
    let mut record = Vec::with_capacity(4 + ciphertext.len());
    record.extend_from_slice(MAGIC);
    record.extend_from_slice(&ciphertext);
    Ok(record)
}

pub fn open(record: &[u8], expected_sid: &str) -> io::Result<RecoveredPassword> {
    if record.len() <= MAGIC.len()
        || record.len() > MAGIC.len() + MAX_CIPHER_BYTES
        || &record[..MAGIC.len()] != MAGIC
    {
        return Err(invalid("invalid vault record"));
    }
    let mut ciphertext = record[MAGIC.len()..].to_vec();
    let mut plaintext = unprotect(&mut ciphertext)?;
    let parsed = (|| {
        if plaintext.len() < 4 {
            return Err(invalid("truncated vault record"));
        }
        let sid_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        if sid_len > MAX_SID_BYTES || plaintext.len() < 4 + sid_len {
            return Err(invalid("invalid vault SID"));
        }
        let sid = std::str::from_utf8(&plaintext[2..2 + sid_len])
            .map_err(|_| invalid("invalid vault SID"))?;
        if sid != expected_sid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "vault account mismatch",
            ));
        }
        let count = u16::from_be_bytes([plaintext[2 + sid_len], plaintext[3 + sid_len]]) as usize;
        if count == 0
            || count * 2 > MAX_PASSWORD_BYTES
            || plaintext.len() != 4 + sid_len + count * 2
        {
            return Err(invalid("invalid vault password length"));
        }
        let utf16: Vec<u16> = plaintext[4 + sid_len..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        if utf16.contains(&0)
            || std::char::decode_utf16(utf16.iter().copied()).any(|unit| unit.is_err())
        {
            return Err(invalid("invalid vault password"));
        }
        Ok(RecoveredPassword { utf16 })
    })();
    plaintext.fill(0);
    parsed
}

pub fn load(path: &Path, expected_sid: &str) -> io::Result<RecoveredPassword> {
    open(&fs::read(path)?, expected_sid)
}

pub fn store_new(path: &Path, sid: &str, password: &[u16]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("vault path has no parent"))?;
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "protected state directory missing",
        ));
    }
    let mut record = seal(sid, password)?;
    let result = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            let result = file.write_all(&record).and_then(|()| file.sync_all());
            drop(file);
            if result.is_err() {
                let _ = fs::remove_file(path);
            }
            result
        }
        Err(error) => Err(error),
    };
    record.fill(0);
    result
}

pub fn replace(path: &Path, sid: &str, password: &[u16]) -> io::Result<()> {
    // Refuse to create a new account vault through the rotation command.
    let existing = load(path, sid)?;
    drop(existing);
    let parent = path
        .parent()
        .ok_or_else(|| invalid("vault path has no parent"))?;
    let mut random = [0u8; 8];
    rand::rng().fill_bytes(&mut random);
    let temp = parent.join(format!(
        ".password_vault.{}.tmp",
        u64::from_le_bytes(random)
    ));
    let mut record = seal(sid, password)?;
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(&record)?;
        file.sync_all()
    })();
    record.fill(0);
    if let Err(error) = written {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    let replaced = fs::rename(&temp, path);
    if replaced.is_err() {
        let _ = fs::remove_file(&temp);
    }
    replaced
}

#[cfg(test)]
mod tests {
    use super::*;
    const SID: &str = "S-1-5-21-123-456-789-1001";

    #[test]
    fn dummy_password_roundtrip_and_account_binding() {
        let record = seal(SID, &"dummy secret 123".encode_utf16().collect::<Vec<_>>()).unwrap();
        assert!(!record.windows(5).any(|part| part == b"dummy"));
        let password = open(&record, SID).unwrap();
        assert_eq!(
            String::from_utf16(&password.utf16).unwrap(),
            "dummy secret 123"
        );
        assert!(open(&record, "S-1-5-21-999-1001").is_err());
    }

    #[test]
    fn corrupted_and_empty_records_fail_closed() {
        assert!(open(b"PKV1", SID).is_err());
        assert!(seal(SID, &[]).is_err());
        let mut record = seal(SID, &[65]).unwrap();
        *record.last_mut().unwrap() ^= 1;
        assert!(open(&record, SID).is_err());
    }

    #[test]
    fn new_store_does_not_replace_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        store_new(&path, SID, &[65]).unwrap();
        assert!(store_new(&path, SID, &[66]).is_err());
        assert_eq!(open(&fs::read(path).unwrap(), SID).unwrap().utf16, vec![65]);
    }

    #[test]
    fn password_rotation_replaces_only_the_same_account_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        assert!(replace(&path, SID, &[66]).is_err());
        store_new(&path, SID, &[65]).unwrap();
        assert!(replace(&path, "S-1-5-21-999-1001", &[66]).is_err());
        assert_eq!(load(&path, SID).unwrap().utf16, vec![65]);
        replace(&path, SID, &[66]).unwrap();
        assert_eq!(load(&path, SID).unwrap().utf16, vec![66]);
    }
}
