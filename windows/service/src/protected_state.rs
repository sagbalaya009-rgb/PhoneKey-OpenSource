//! Runtime enforcement of the installer's protected-state namespace.
//! Administrators and LocalSystem are trusted; ordinary users may not mutate it.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetDriveTypeW, GetFileInformationByHandle,
};

pub struct ProtectedStateGuard {
    // No FILE_SHARE_DELETE: the checked namespace stays pinned through shutdown.
    _handles: Vec<File>,
}

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn win(error: windows::core::Error) -> io::Error {
    io::Error::other(error)
}

fn local_components(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut parts = path.components();
    let drive = match parts.next() {
        Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)) => p.as_os_str(),
        _ => {
            return Err(denied(
                "protected state requires a normal absolute drive path",
            ));
        }
    };
    if parts.next() != Some(Component::RootDir) {
        return Err(denied("protected state path must be absolute"));
    }
    let mut current = PathBuf::from(drive);
    current.push(r"\");
    let mut paths = vec![current.clone()];
    for part in parts {
        match part {
            Component::Normal(name) => current.push(name),
            _ => return Err(denied("protected state path contains unsafe components")),
        }
        paths.push(current.clone());
    }
    Ok(paths)
}
fn open_pinned(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        // Metadata-only access does not establish the share-access exclusion
        // required here. Bit 0x1 is FILE_LIST_DIRECTORY for directories and
        // FILE_READ_DATA for files: participate in sharing checks without
        // requesting write/delete access or actually reading state contents.
        .access_mode(0x0002_0081) // READ_CONTROL | FILE_READ_ATTRIBUTES | read/list
        .share_mode(3) // read + write, never delete
        .custom_flags(0x0220_0000) // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        .open(path)
}
fn validate_metadata(file: &File, directory: bool) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }.map_err(win)?;
    if info.dwFileAttributes & 0x400 != 0 {
        return Err(denied(
            "reparse points are forbidden in protected state paths",
        ));
    }
    if (info.dwFileAttributes & 0x10 != 0) != directory {
        return Err(denied("protected state object has the wrong file type"));
    }
    if !directory && info.nNumberOfLinks != 1 {
        return Err(denied(
            "protected state files must have exactly one hard link",
        ));
    }
    Ok(())
}
unsafe fn trusted_sid(sid: PSID) -> bool {
    unsafe {
        !sid.0.is_null()
            && IsValidSid(sid).as_bool()
            && (IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool())
    }
}
unsafe fn validate_descriptor(sd: PSECURITY_DESCRIPTOR, directory: bool) -> io::Result<()> {
    unsafe {
        if !IsValidSecurityDescriptor(sd).as_bool() {
            return Err(denied("invalid state security descriptor"));
        }
        let mut owner = PSID::default();
        let mut defaulted = windows::core::BOOL(0);
        GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted).map_err(win)?;
        if !trusted_sid(owner) {
            return Err(denied(
                "protected state owner is not SYSTEM or Administrators",
            ));
        }
        let mut control = SECURITY_DESCRIPTOR_CONTROL(0);
        let mut revision = 0;
        GetSecurityDescriptorControl(sd, &mut control.0, &mut revision).map_err(win)?;
        if directory && control.0 & SE_DACL_PROTECTED.0 == 0 {
            return Err(denied(
                "protected state directory must disable inherited permissions",
            ));
        }
        let mut present = windows::core::BOOL(0);
        let mut acl = std::ptr::null_mut::<ACL>();
        GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted).map_err(win)?;
        if !present.as_bool() || acl.is_null() || !IsValidAcl(acl).as_bool() {
            return Err(denied("protected state requires a valid non-null DACL"));
        }
        let mut system_full = false;
        for index in 0..(*acl).AceCount {
            let mut ace = std::ptr::null_mut();
            GetAce(acl, u32::from(index), &mut ace).map_err(win)?;
            let header = &*(ace as *const ACE_HEADER);
            // Only simple allow/deny ACEs are part of the deployment policy.
            if !matches!(header.AceType, 0 | 1) || header.AceSize < 16 {
                return Err(denied("unsupported protected state ACE"));
            }
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            let sid = PSID(std::ptr::addr_of!(allowed.SidStart) as *mut _);
            let sid_bytes = sid.0 as *const u8;
            let sid_length = 8usize + 4usize * usize::from(*sid_bytes.add(1));
            if 8 + sid_length > usize::from(header.AceSize) || !IsValidSid(sid).as_bool() {
                return Err(denied("invalid protected state ACE SID"));
            }
            if header.AceType == 0 {
                // Includes inherit-only grants: future state files must be safe too.
                if !trusted_sid(sid) && allowed.Mask & 0x500d_0156 != 0 {
                    return Err(denied("ordinary users can modify protected state"));
                }
                if header.AceFlags & 8 == 0
                    && IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
                    && (allowed.Mask & 0x1000_0000 != 0
                        || allowed.Mask & 0x001f_01ff == 0x001f_01ff)
                {
                    system_full = true;
                }
            }
        }
        if !system_full {
            return Err(denied(
                "protected state lacks an explicit SYSTEM full-control grant",
            ));
        }
        Ok(())
    }
}
fn validate_acl(file: &File, directory: bool) -> io::Result<()> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let result = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut sd),
        )
    };
    if result.0 != 0 {
        return Err(io::Error::from_raw_os_error(result.0 as i32));
    }
    let checked = unsafe { validate_descriptor(sd, directory) };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    checked
}
impl ProtectedStateGuard {
    pub fn production() -> io::Result<Self> {
        let identity = crate::state::windows_identity_path()?;
        let state = identity
            .parent()
            .ok_or_else(|| denied("state path has no parent"))?;
        let paths = local_components(state)?;
        let drive: Vec<u16> = paths[0].as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe { GetDriveTypeW(windows::core::PCWSTR(drive.as_ptr())) } != 3 {
            return Err(denied("protected state requires a fixed local drive"));
        }
        if paths.len() < 3 {
            return Err(denied("protected state namespace is incomplete"));
        }
        let mut handles = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            let file = open_pinned(path)?; // Never create or repair directories here.
            validate_metadata(&file, true)?;
            if index >= paths.len() - 2 {
                validate_acl(&file, true)?;
            }
            handles.push(file);
        }
        for name in [
            "windows_identity.json",
            "trusted_phone.json",
            "authorized_account.json",
        ] {
            match open_pinned(&state.join(name)) {
                Ok(file) => {
                    validate_metadata(&file, false)?;
                    validate_acl(&file, false)?;
                    handles.push(file);
                }
                Err(error) if error.raw_os_error() == Some(2) => (), // Fresh state allowed.
                Err(error) => return Err(error),
            }
        }
        // The vault can be atomically replaced when the owner changes the
        // Microsoft-account password. Its protected parent stays pinned, and
        // its ACL and file type are checked before the service starts.
        for name in ["password_vault.bin", "password_vault_local.bin"] {
            match open_pinned(&state.join(name)) {
                Ok(file) => {
                    validate_metadata(&file, false)?;
                    validate_acl(&file, false)?;
                }
                Err(error) if error.raw_os_error() == Some(2) => (),
                Err(error) => return Err(error),
            }
        }
        Ok(Self { _handles: handles })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    fn check(sddl: &str) -> io::Result<()> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                windows::core::PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
            .unwrap();
            let result = validate_descriptor(sd, true);
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            result
        }
    }
    #[test]
    fn accepts_deployment_directory_policy() {
        check("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").unwrap();
    }
    #[test]
    fn rejects_untrusted_owner() {
        assert!(check("O:BUG:BAD:P(A;;FA;;;SY)").is_err());
    }
    #[test]
    fn rejects_inherited_directory_acl() {
        assert!(check("O:SYG:SYD:(A;;FA;;;SY)").is_err());
    }
    #[test]
    fn rejects_null_dacl() {
        assert!(check("O:SYG:SYD:NO_ACCESS_CONTROL").is_err());
    }
    #[test]
    fn rejects_untrusted_modification_rights() {
        for mask in [
            2u32, 4, 16, 64, 256, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000,
        ] {
            assert!(
                check(&format!("O:SYG:SYD:P(A;;FA;;;SY)(A;;0x{mask:x};;;BU)")).is_err(),
                "mask {mask:x}"
            );
        }
    }
    #[test]
    fn rejects_unsafe_child_inheritance() {
        assert!(check("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OIIO;FW;;;BU)").is_err());
    }
    #[test]
    fn accepts_read_only_users() {
        check("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;;FR;;;BU)").unwrap();
    }
    #[test]
    fn rejects_missing_system_access() {
        assert!(check("O:BAG:BAD:P(A;;FA;;;BA)").is_err());
    }
    #[test]
    fn rejects_nonlocal_or_relative_paths() {
        for path in [
            r"relative\state",
            r"C:state",
            r"\\server\share\state",
            r"\\?\C:\state",
            r"C:\parent\..\state",
        ] {
            assert!(local_components(Path::new(path)).is_err(), "{path}");
        }
    }
    #[test]
    fn pinned_handle_prevents_rename() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("state");
        let to = root.path().join("moved");
        std::fs::create_dir(&from).unwrap();
        let handle = open_pinned(&from).unwrap();
        assert_eq!(
            std::fs::rename(&from, &to).unwrap_err().raw_os_error(),
            Some(32)
        );
        drop(handle);
        std::fs::rename(&from, &to).unwrap();
    }
    #[test]
    fn rejects_hardlinked_state_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state.json");
        std::fs::write(&path, b"{}").unwrap();
        std::fs::hard_link(&path, root.path().join("alias")).unwrap();
        assert!(validate_metadata(&open_pinned(&path).unwrap(), false).is_err());
    }
    #[test]
    fn missing_directory_is_not_created() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing");
        assert!(open_pinned(&path).is_err());
        assert!(!path.exists());
    }
    #[test]
    fn pinned_directory_prevents_delete_until_handle_is_dropped() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state");
        std::fs::create_dir(&path).unwrap();
        let handle = open_pinned(&path).unwrap();
        assert_eq!(
            std::fs::remove_dir(&path).unwrap_err().raw_os_error(),
            Some(32)
        );
        assert!(path.is_dir());
        drop(handle);
        std::fs::remove_dir(&path).unwrap();
    }
    #[test]
    fn pinned_file_prevents_rename_and_delete_until_handle_is_dropped() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state.json");
        let moved = root.path().join("moved.json");
        std::fs::write(&path, b"unchanged").unwrap();
        let handle = open_pinned(&path).unwrap();
        assert_eq!(
            std::fs::rename(&path, &moved).unwrap_err().raw_os_error(),
            Some(32)
        );
        assert_eq!(
            std::fs::remove_file(&path).unwrap_err().raw_os_error(),
            Some(32)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"unchanged");
        drop(handle);
        std::fs::rename(&path, &moved).unwrap();
        std::fs::remove_file(&moved).unwrap();
    }
    #[test]
    fn existing_delete_access_prevents_pin_acquisition() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state");
        std::fs::create_dir(&path).unwrap();
        let conflicting = OpenOptions::new()
            .access_mode(0x0001_0000) // DELETE, but do not perform a deletion.
            .share_mode(7)
            .custom_flags(0x0220_0000)
            .open(&path)
            .unwrap();
        assert_eq!(open_pinned(&path).unwrap_err().raw_os_error(), Some(32));
        drop(conflicting);
        let pinned = open_pinned(&path).unwrap();
        validate_metadata(&pinned, true).unwrap();
    }
}
