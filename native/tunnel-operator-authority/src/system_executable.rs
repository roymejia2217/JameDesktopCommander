//! Native, read-only Windows system-executable evidence for issue #270.
//! Never treat a path, file ID or hardlink count as permission to spawn.
use crate::{OsSystemExecutableObservation, SidObservationError};
use std::{
    ffi::OsString,
    iter, mem,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf, Prefix},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DEVICE,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::SystemInformation::GetSystemDirectoryW,
};

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: exclusively owns the successful CreateFileW handle.
        unsafe { CloseHandle(self.0) };
    }
}
/// Ask the kernel for its system directory, never an environment variable.
fn native_system_directory() -> Result<PathBuf, SidObservationError> {
    let mut chars = vec![0u16; 32_768];
    // SAFETY: Windows writes at most the provided UTF-16 code unit capacity.
    let length = unsafe { GetSystemDirectoryW(chars.as_mut_ptr(), chars.len() as u32) } as usize;
    if length == 0 || length >= chars.len() || chars[..length].contains(&0) {
        return Err(SidObservationError::Unverifiable);
    }
    let directory = PathBuf::from(OsString::from_wide(&chars[..length]));
    let local_disk = matches!(
        directory.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    );
    if !directory.is_absolute() || !local_disk {
        return Err(SidObservationError::Unverifiable);
    }
    Ok(directory)
}

fn regular_file_attributes(attributes: u32, links: u32) -> Result<(), SidObservationError> {
    if links == 0
        || attributes
            & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)
            != 0
    {
        return Err(SidObservationError::Unverifiable);
    }
    // Windows OS binaries may legitimately share hard links with WinSxS.
    // Report links without treating link count as proof of package ownership.
    Ok(())
}
fn observe_file_handle(path: &Path) -> Result<OsSystemExecutableObservation, SidObservationError> {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    if wide.len() > 32_768 || wide[..wide.len() - 1].contains(&0) {
        return Err(SidObservationError::Unverifiable);
    }
    // SAFETY: bounded NUL-terminated absolute Win32 path; read only. OPEN_REPARSE_POINT
    // exposes a final-component symlink/junction rather than silently following it.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(SidObservationError::Unverifiable);
    }
    let _handle = OwnedHandle(handle);
    // SAFETY: zero is a valid initialization for this Win32 output-only POD.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    // SAFETY: the kernel fills metadata for the live handle; no path reopen.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(SidObservationError::Unverifiable);
    }
    regular_file_attributes(info.dwFileAttributes, info.nNumberOfLinks)?;
    Ok(OsSystemExecutableObservation {
        path: path.to_path_buf(),
        volume_serial: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        link_count: info.nNumberOfLinks,
    })
}
pub(super) fn observe() -> Result<OsSystemExecutableObservation, SidObservationError> {
    let path = native_system_directory()?.join("schtasks.exe");
    observe_file_handle(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_metadata_rejects_reparse_directory_and_invalid_identity() {
        assert_eq!(regular_file_attributes(FILE_ATTRIBUTE_NORMAL, 1), Ok(()));
        assert_eq!(regular_file_attributes(FILE_ATTRIBUTE_NORMAL, 2), Ok(()));
        for (attrs, links) in [
            (FILE_ATTRIBUTE_REPARSE_POINT, 1),
            (FILE_ATTRIBUTE_DIRECTORY, 1),
            (FILE_ATTRIBUTE_DEVICE, 1),
            (FILE_ATTRIBUTE_NORMAL, 0),
            (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY, 1),
        ] {
            assert_eq!(
                regular_file_attributes(attrs, links),
                Err(SidObservationError::Unverifiable)
            );
        }
    }

    #[test]
    fn observed_file_handle_rejects_directory_and_missing_path() {
        let root = tempfile::tempdir().expect("fixture root");
        assert_eq!(
            observe_file_handle(root.path()),
            Err(SidObservationError::Unverifiable)
        );
        assert_eq!(
            observe_file_handle(&root.path().join("nonexistent.exe")),
            Err(SidObservationError::Unverifiable),
        );
    }
}
