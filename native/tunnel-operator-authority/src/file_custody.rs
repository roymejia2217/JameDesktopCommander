//! Non-shipping, fixture-rooted, read-only Win32 file custody evidence.
//! The caller-provided root is not authenticated. A positive observation is
//! NOT protection against same-SID attackers or subsequent namespace races.
use crate::{observe_current_process_user_sid, FileCustodyDenied, FileCustodyEvidence};
use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    mem,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Component, Path, Prefix},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_SUCCESS, HANDLE},
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        GetAce, IsValidSid, IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    },
    Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
};
// Standard ACCESS_ALLOWED_ACE_TYPE and ACCESS_DENIED_ACE_TYPE values (WinNT.h).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

fn denied() -> FileCustodyDenied {
    FileCustodyDenied::Unverifiable
}

struct OwnedSecurityDescriptor(*mut c_void);
impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo returns a LocalFree-owned allocation.
        unsafe { LocalFree(self.0) };
    }
}

fn safe_relative_components(path: &Path) -> Result<Vec<&std::ffi::OsStr>, FileCustodyDenied> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(denied());
        };
        let word = value.to_str().ok_or_else(denied)?;
        let base = word.split('.').next().unwrap_or("").to_ascii_uppercase();
        if word.is_empty()
            || word.ends_with(['.', ' '])
            || word.contains(':')
            || matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (base.len() == 4
                && (base.starts_with("COM") || base.starts_with("LPT"))
                && base.as_bytes()[3].is_ascii_digit()
                && base.as_bytes()[3] != b'0')
        {
            return Err(denied());
        }
        parts.push(value);
        if parts.len() > 32 {
            return Err(denied());
        }
    }
    if parts.is_empty() {
        return Err(denied());
    }
    Ok(parts)
}
fn open_metadata(path: &Path, directory: bool) -> Result<File, FileCustodyDenied> {
    // Attribute/security-only access. The file's contents are never opened
    // with FILE_READ_DATA and the target is held without FILE_SHARE_DELETE.
    let file = OpenOptions::new()
        .access_mode(0x0002_0080) // READ_CONTROL | FILE_READ_ATTRIBUTES
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| denied())?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    // SAFETY: the owned file handle is valid; the structure is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(denied());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(denied());
    }
    Ok(file)
}

fn sid_allowed(sid: *mut c_void, token_user: &[u8]) -> bool {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return false;
    }
    // SAFETY: Windows validated the SID and the kernel-supplied byte count.
    let size = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) } as usize;
    if !(12..=256).contains(&size) {
        return false;
    }
    let bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), size) };
    bytes == token_user
        || unsafe {
            IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
        }
}
fn private_owner_and_dacl(file: &File, token_user: &[u8]) -> Result<(), FileCustodyDenied> {
    let (mut owner, mut dacl, mut sd) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    // SAFETY: all outputs are writable; security descriptor is LocalFree-owned.
    // Security is fetched from the already-opened handle, not a second path.
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    let _descriptor = OwnedSecurityDescriptor(sd);
    if result != ERROR_SUCCESS || sd.is_null() || dacl.is_null() || !sid_allowed(owner, token_user)
    {
        return Err(denied());
    }

    // Fail closed on absent/null or oversized ACLs, including exotic ACEs.
    let acl: &ACL = unsafe { &*dacl };
    if (acl.AclSize as usize) < mem::size_of::<ACL>() || acl.AclSize > 8192 || acl.AceCount > 64 {
        return Err(denied());
    }
    for i in 0..u32::from(acl.AceCount) {
        let mut ace: *mut c_void = ptr::null_mut();
        if unsafe { GetAce(dacl, i, &mut ace) } == 0 || ace.is_null() {
            return Err(denied());
        }
        let header = unsafe { ptr::read_unaligned(ace.cast::<ACE_HEADER>()) };
        if header.AceSize < mem::size_of::<ACE_HEADER>() as u16 || header.AceSize > acl.AclSize {
            return Err(denied());
        }
        let is_allow = match header.AceType {
            ACCESS_ALLOWED_ACE_TYPE => true,
            ACCESS_DENIED_ACE_TYPE => false,
            _ => return Err(denied()),
        };
        let offset = mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let ace_len = header.AceSize as usize;
        if ace_len < offset + 12 || ace_len > 8192 {
            return Err(denied());
        }
        let raw = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), ace_len) };
        let sid_tail = &raw[offset..];
        if sid_tail[0] != 1 || !(1..=15).contains(&sid_tail[1]) {
            return Err(denied());
        }
        let sid_len = 8 + usize::from(sid_tail[1]) * 4;
        if sid_len > sid_tail.len() {
            return Err(denied());
        }
        let sid = unsafe { ace.cast::<u8>().add(offset).cast::<c_void>() };
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(denied());
        }
        if is_allow && !sid_allowed(sid, token_user) {
            return Err(denied());
        }
    }
    Ok(())
}

pub(super) fn observe(
    root: &Path,
    relative: &Path,
) -> Result<FileCustodyEvidence, FileCustodyDenied> {
    if !root.is_absolute()
        || root.as_os_str().len() > 2048
        || root
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        || !matches!(root.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
    {
        return Err(denied());
    }
    let parts = safe_relative_components(relative)?;
    let user = observe_current_process_user_sid().map_err(|_| denied())?;
    let first = open_metadata(root, true)?;
    private_owner_and_dacl(&first, &user)?;
    let mut held: Vec<File> = vec![first];
    let mut current = root.to_path_buf();
    for (index, part) in parts.iter().enumerate() {
        current.push(part);
        let directory = index + 1 != parts.len();
        let file = open_metadata(&current, directory)?;
        private_owner_and_dacl(&file, &user)?;
        held.push(file);
    }
    // Handles stayed open without FILE_SHARE_DELETE while each component
    // was inspected. This does not bind an independently trusted root, deny
    // same-SID reconfiguration, or prevent races after all handles close.
    Ok(FileCustodyEvidence::ObservedOnly)
}
