use crate::SidObservationError;
use std::{ffi::c_void, mem, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE},
    Security::{GetTokenInformation, IsValidSid, TokenUser, TOKEN_QUERY, TOKEN_USER},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

const MAX_TOKEN_INFO_BYTES: usize = 4096;

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper exclusively owns the handle from OpenProcessToken.
        unsafe { CloseHandle(self.0) };
    }
}

/// Accept a single, exact-length, structurally bounded binary Windows SID.
/// This is shape validation only, not identity validation or authorization.
pub(crate) fn valid_sid_bytes(sid: &[u8]) -> bool {
    if sid.len() < 12 || sid[0] != 1 || !(1..=15).contains(&sid[1]) {
        return false;
    }
    sid.len() == 8 + usize::from(sid[1]) * 4
}
fn open_process_token() -> Result<OwnedHandle, SidObservationError> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: current pseudo-process handle is valid and token is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0
        || token.is_null()
    {
        return Err(SidObservationError::Unverifiable);
    }
    Ok(OwnedHandle(token))
}

pub(crate) fn observe_current_process_user_sid() -> Result<Vec<u8>, SidObservationError> {
    let token = open_process_token()?;
    let mut required = 0u32;
    // SAFETY: documented size query; the output pointer is null with length zero.
    let initial =
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required) };
    if initial != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || (required as usize) < mem::size_of::<TOKEN_USER>()
        || (required as usize) > MAX_TOKEN_INFO_BYTES
    {
        return Err(SidObservationError::Unverifiable);
    }
    let word_size = mem::size_of::<usize>();
    let mut buffer = vec![0usize; (required as usize).div_ceil(word_size)];
    let mut received = 0u32;
    // SAFETY: the aligned buffer owns at least required bytes; output is bounded.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            required,
            &mut received,
        )
    };
    if ok == 0 || received < mem::size_of::<TOKEN_USER>() as u32 || received > required {
        return Err(SidObservationError::Unverifiable);
    }
    // SAFETY: the successful kernel query wrote TOKEN_USER at the buffer base.
    let user = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let start = buffer.as_ptr() as usize;
    let sid_offset = (user.User.Sid as usize)
        .checked_sub(start)
        .ok_or(SidObservationError::Unverifiable)?;
    let minimum = sid_offset
        .checked_add(8)
        .ok_or(SidObservationError::Unverifiable)?;
    if minimum > received as usize {
        return Err(SidObservationError::Unverifiable);
    }
    // SAFETY: the validated offset and length lie inside the returned buffer.
    let full =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), received as usize) };
    let count = full[sid_offset + 1] as usize;
    let sid_length = 8usize
        .checked_add(
            count
                .checked_mul(4)
                .ok_or(SidObservationError::Unverifiable)?,
        )
        .ok_or(SidObservationError::Unverifiable)?;
    let sid_end = sid_offset
        .checked_add(sid_length)
        .ok_or(SidObservationError::Unverifiable)?;
    if sid_end > received as usize || !valid_sid_bytes(&full[sid_offset..sid_end]) {
        return Err(SidObservationError::Unverifiable);
    }
    // SAFETY: the SID is structurally validated and fully contained in memory.
    if unsafe { IsValidSid(user.User.Sid) } == 0 {
        return Err(SidObservationError::Unverifiable);
    }
    Ok(full[sid_offset..sid_end].to_vec())
}
