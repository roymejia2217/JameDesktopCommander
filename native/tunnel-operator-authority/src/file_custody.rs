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
        CreateWellKnownSid, GetSecurityDescriptorControl, GetSecurityDescriptorLength,
        IsValidSecurityDescriptor, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SE_SELF_RELATIVE,
        WELL_KNOWN_SID_TYPE,
    },
    Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
};
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

fn known_windows_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<Vec<u8>, FileCustodyDenied> {
    let mut buffer = [0u8; 256];
    let mut received = buffer.len() as u32;
    // SAFETY: CreateWellKnownSid writes at most the caller-provided buffer size.
    if unsafe {
        CreateWellKnownSid(
            kind,
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut received,
        )
    } == 0
        || !(12..=256).contains(&received)
    {
        return Err(denied());
    }
    let sid = &buffer[..received as usize];
    if !crate::windows::valid_sid_bytes(sid) {
        return Err(denied());
    }
    Ok(sid.to_vec())
}

fn private_owner_and_dacl(file: &File, token_user: &[u8]) -> Result<(), FileCustodyDenied> {
    let mut sd: *mut c_void = ptr::null_mut();
    // SAFETY: all requested fields are returned in one LocalFree-owned descriptor.
    // Use the already-opened file handle, not another pathname lookup.
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    };
    let _descriptor = OwnedSecurityDescriptor(sd);
    if result != ERROR_SUCCESS || sd.is_null() {
        return Err(denied());
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: GetSecurityInfo owns a live descriptor until _descriptor drops.
    if unsafe { IsValidSecurityDescriptor(sd) } == 0
        || unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0
        || control & SE_SELF_RELATIVE == 0
    {
        return Err(denied());
    }
    // The Windows API determines the exact allocation length. Refuse oversized
    // results before copying; the copied descriptor is parsed with safe slices.
    let length = unsafe { GetSecurityDescriptorLength(sd) } as usize;
    if !(20..=32768).contains(&length) {
        return Err(denied());
    }
    let mut owned = vec![0u8; length];
    // SAFETY: Windows validated the live self-relative descriptor, and the
    // bounded GetSecurityDescriptorLength result defines the source range.
    unsafe { ptr::copy_nonoverlapping(sd.cast::<u8>(), owned.as_mut_ptr(), length) };
    let system = known_windows_sid(WinLocalSystemSid)?;
    let administrators = known_windows_sid(WinBuiltinAdministratorsSid)?;
    if !crate::relative_sd::private_acl(&owned, token_user, &system, &administrators) {
        return Err(denied());
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
