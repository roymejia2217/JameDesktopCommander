//! Verify a supplied Windows administrative parent against OS-known ProgramData.
//! NON-ISSUING: OS known-folder identity is necessary, not an authorized policy.
use crate::IdentityDenied;
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    os::windows::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
    ptr,
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    },
    System::Com::{CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED},
    UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath, KF_FLAG_DEFAULT},
};

struct ScopedComApartment;
impl ScopedComApartment {
    fn begin() -> Result<Self, IdentityDenied> {
        // Windows documents that this API requires initialized COM on the
        // calling thread. A conflicting apartment configuration denies.
        let hr = unsafe { CoInitializeEx(ptr::null(), COINIT_MULTITHREADED as u32) };
        if hr < 0 {
            return Err(IdentityDenied);
        }
        Ok(Self)
    }
}
impl Drop for ScopedComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

// SHGetKnownFolderPath uses COM's allocator; never call LocalFree/free.
struct OwnedKnownFolderPath(*mut u16);
impl Drop for OwnedKnownFolderPath {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CoTaskMemFree(self.0.cast()) };
        }
    }
}

fn open_os_program_data() -> Result<File, IdentityDenied> {
    let _com = ScopedComApartment::begin()?;
    let mut raw = ptr::null_mut();
    // SAFETY: the GUID is static, the out-pointer is valid, and a null user
    // token selects the common OS folder rather than caller-supplied input.
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramData,
            KF_FLAG_DEFAULT as u32,
            ptr::null_mut(),
            &mut raw,
        )
    };
    let path_ptr = OwnedKnownFolderPath(raw);
    if hr != 0 || path_ptr.0.is_null() {
        return Err(IdentityDenied);
    }
    let mut len = 0usize;
    // SAFETY: a successful shell call guarantees a NUL-terminated,
    // CoTaskMem-allocated UTF-16 string. Reject zero/oversized paths.
    while len < 32767 && unsafe { *path_ptr.0.add(len) } != 0 {
        len += 1;
    }
    if len == 0 || len >= 32767 {
        return Err(IdentityDenied);
    }
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(path_ptr.0, len)
    }));
    if !path.is_absolute() {
        return Err(IdentityDenied);
    }
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)
        .map_err(|_| IdentityDenied)?;
    let metadata = opened.metadata().map_err(|_| IdentityDenied)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(IdentityDenied);
    }
    Ok(opened)
}

/// Check actual kernel file identity, not a caller-provided parent path.
/// This cannot authenticate the chosen child name, OS admin provisioning,
/// concurrent replacement or an atomic filesystem operation.
pub(crate) fn verify_system_program_data_parent(parent: &File) -> Result<(), IdentityDenied> {
    let expected = open_os_program_data()?;
    crate::windows_policy_root::verify_preopened_same_directory_identity(parent, &expected)
}
