//! Read-only, handle-relative Windows NTFS volume mountpoint classifier.
//! NON-ISSUING: this check never grants access or changes filesystem objects.
use crate::IdentityDenied;
use std::{
    fs::File,
    mem,
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            NtCreateFile, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        },
    },
    Win32::{
        Foundation::{OBJ_CASE_INSENSITIVE, UNICODE_STRING},
        Storage::FileSystem::{
            FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_TAG_INFO, FILE_READ_ATTRIBUTES, FILE_READ_EA, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, MAXIMUM_REPARSE_DATA_BUFFER_SIZE,
        },
        System::{
            Ioctl::FSCTL_GET_REPARSE_POINT,
            IO::{DeviceIoControl, IO_STATUS_BLOCK},
        },
    },
};

// The shared reparse tag applies to junctions *and* volume mount points.
// The independently validated substitute name must denote a volume root.
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xa000_0003;

fn is_volume_root_mount_data(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }
    let u16_at = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]) as usize;
    let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let data_len = u16_at(4);
    if tag != IO_REPARSE_TAG_MOUNT_POINT || data_len + 8 != data.len() {
        return false;
    }
    let (sub_start, sub_len) = (u16_at(8), u16_at(10));
    let (print_start, print_len) = (u16_at(12), u16_at(14));
    let path = &data[16..];
    if [sub_start, sub_len, print_start, print_len]
        .iter()
        .any(|n| n % 2 != 0)
        || sub_len == 0
        || sub_start
            .checked_add(sub_len)
            .is_none_or(|n| n > path.len())
        || print_start
            .checked_add(print_len)
            .is_none_or(|n| n > path.len())
    {
        return false;
    }
    let units: Vec<_> = path[sub_start..sub_start + sub_len]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let Ok(name) = String::from_utf16(&units) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    let Some(guid) = lower
        .strip_prefix(r"\??\volume{")
        .and_then(|tail| tail.strip_suffix(r"}\"))
    else {
        return false;
    };
    guid.len() == 36
        && guid.bytes().enumerate().all(|(i, byte)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// Inspect the named entry itself relative to an already open parent.
/// Normal directory entries need no reparse proof; reparse entries must
/// explicitly point to a Volume GUID root, never an arbitrary directory.
pub(crate) fn verify_named_volume_mount_entry(
    parent: &File,
    child: &str,
) -> Result<(), IdentityDenied> {
    if child.is_empty()
        || child.len() > 64
        || !child
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(IdentityDenied);
    }
    let mut name: Vec<u16> = child.encode_utf16().collect();
    let len = u16::try_from(name.len() * 2).map_err(|_| IdentityDenied)?;
    let native_name = UNICODE_STRING {
        Length: len,
        MaximumLength: len,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle().cast(),
        ObjectName: &native_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle = ptr::null_mut();
    let mut io: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    // SAFETY: buffers and parent handle are live, relative name is exactly
    // one component, and the syscall only opens an existing directory entry.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_READ_ATTRIBUTES | FILE_READ_EA,
            &attributes,
            &mut io,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            ptr::null(),
            0,
        )
    };
    if status < 0 || handle.is_null() || handle as isize == -1 {
        return Err(IdentityDenied);
    }
    // SAFETY: NtCreateFile returned an owned, valid handle on success.
    let entry = unsafe { File::from_raw_handle(handle) };

    let mut info: FILE_ATTRIBUTE_TAG_INFO = unsafe { mem::zeroed() };
    // SAFETY: the owned entry handle is live; output points to a fixed-size
    // initialized structure; this call retrieves metadata only.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            entry.as_raw_handle().cast(),
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(IdentityDenied);
    }
    if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return Ok(());
    }
    if info.ReparseTag != IO_REPARSE_TAG_MOUNT_POINT {
        return Err(IdentityDenied);
    }
    let mut data = [0u8; MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize];
    let mut returned = 0u32;
    // SAFETY: entry is owned and live, the writable fixed buffer is bounded,
    // and a synchronous read-only FSCTL is used (no OVERLAPPED lifetime).
    let ok = unsafe {
        DeviceIoControl(
            entry.as_raw_handle().cast(),
            FSCTL_GET_REPARSE_POINT,
            ptr::null(),
            0,
            data.as_mut_ptr().cast(),
            data.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    let checked = data.get(..returned as usize).ok_or(IdentityDenied)?;
    if ok == 0 || !is_volume_root_mount_data(checked) {
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic REPARSE_DATA_BUFFER in the exact documented Win32 layout.
    // These are parser guards, not a claim of a mounted VHD positive.
    fn reparse_data(tag: u32, substitute: &str) -> Vec<u8> {
        let name: Vec<u8> = substitute
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let payload_len = 8 + name.len() + 2; // trailing UTF-16 NUL
        let mut result = vec![0u8; 16 + name.len() + 2];
        result[..4].copy_from_slice(&tag.to_le_bytes());
        result[4..6].copy_from_slice(&(payload_len as u16).to_le_bytes());
        result[8..10].copy_from_slice(&0u16.to_le_bytes());
        result[10..12].copy_from_slice(&(name.len() as u16).to_le_bytes());
        result[12..14].copy_from_slice(&((name.len() + 2) as u16).to_le_bytes());
        result[14..16].copy_from_slice(&0u16.to_le_bytes());
        result[16..16 + name.len()].copy_from_slice(&name);
        result
    }

    #[test]
    fn accepts_only_exact_volume_guid_root_substitute_name() {
        let guid = r"\??\Volume{12345678-1234-abcd-ef12-9876543210ab}\";
        let vhd = reparse_data(IO_REPARSE_TAG_MOUNT_POINT, guid);
        assert!(is_volume_root_mount_data(&vhd));
        assert!(!is_volume_root_mount_data(&reparse_data(
            IO_REPARSE_TAG_MOUNT_POINT,
            r"\??\C:\temp\outside"
        )));
        assert!(!is_volume_root_mount_data(&reparse_data(
            IO_REPARSE_TAG_MOUNT_POINT,
            &(guid.to_owned() + "arbitrary")
        )));
        assert!(!is_volume_root_mount_data(&reparse_data(
            IO_REPARSE_TAG_MOUNT_POINT,
            r"\??\Volume{not-a-guid}\"
        )));
        assert!(
            !is_volume_root_mount_data(&reparse_data(0xa000_000c, guid)),
            "directory symlink is not a mountpoint"
        );
    }

    #[test]
    fn malformed_reparse_metadata_never_grants_mount_provenance() {
        let mut valid = reparse_data(
            IO_REPARSE_TAG_MOUNT_POINT,
            r"\??\Volume{12345678-1234-abcd-ef12-9876543210ab}\",
        );
        for len in 0..16 {
            assert!(!is_volume_root_mount_data(&valid[..len]));
        }
        valid[10] = 1;
        assert!(!is_volume_root_mount_data(&valid), "odd UTF-16 length");
        valid[10] = 0;
        valid[11] = 0xff;
        assert!(!is_volume_root_mount_data(&valid), "out-of-bounds name");
        let mut mismatched = reparse_data(
            IO_REPARSE_TAG_MOUNT_POINT,
            r"\??\Volume{12345678-1234-abcd-ef12-9876543210ab}\",
        );
        mismatched[4] = 0;
        mismatched[5] = 0;
        assert!(!is_volume_root_mount_data(&mismatched), "wrong data size");
    }
}
