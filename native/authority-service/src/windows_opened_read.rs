//! Native Windows read of an already-opened regular-file HANDLE.
//! This consumes file custody; no pathname lookup/reopen occurs here.
//! It does NOT authenticate the caller, establish protected storage origin,
//! authorize a root or bypass #139/#148's still-unmet service/revocation gates.
use crate::confined_read::ReadDenied;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem::MaybeUninit,
    os::windows::{fs::MetadataExt, io::AsRawHandle},
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
};

const MAX_BYTES: usize = 1024 * 1024;

fn single_link(file: &File) -> Result<bool, ReadDenied> {
    let mut info = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
        return Err(ReadDenied);
    }
    Ok(unsafe { info.assume_init() }.nNumberOfLinks == 1)
}

/// Read one OS file object already opened by the trusted authority.
/// The caller must establish storage provenance, policy and caller identity
/// BEFORE passing the owned File; this function does not grant authority.
pub fn read_opened_regular(mut file: File) -> Result<Vec<u8>, ReadDenied> {
    let before = file.metadata().map_err(|_| ReadDenied)?;
    if !before.is_file()
        || before.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !single_link(&file)?
        || before.len() > MAX_BYTES as u64
    {
        return Err(ReadDenied);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| ReadDenied)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadDenied)?;
    if bytes.len() > MAX_BYTES {
        return Err(ReadDenied);
    }
    let after = file.metadata().map_err(|_| ReadDenied)?;
    if !after.is_file()
        || after.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !single_link(&file)?
        || after.len() != before.len()
        || bytes.len() as u64 != after.len()
    {
        // This detects observed concurrent changes. It cannot prove exclusive
        // access or defeat an independently writable hard-link race.
        return Err(ReadDenied);
    }
    Ok(bytes)
}
