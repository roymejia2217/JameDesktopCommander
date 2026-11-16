//! Test-only Windows named-pipe peer token observation, non-authorizing.
//! The caller MUST read a complete request before calling this function.
//! It is not a production broker grant, policy lookup or SID-based client origin.
use crate::{
    token_policy::{bounded_buffer_span, bounded_sid_bytes},
    IdentityDenied,
};
use std::{
    mem::{size_of, MaybeUninit},
    os::windows::io::{AsRawHandle, BorrowedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE},
    Security::{
        GetTokenInformation, RevertToSelf, SecurityIdentification, TokenImpersonation,
        TokenImpersonationLevel, TokenType, TokenUser, TOKEN_QUERY, TOKEN_USER,
    },
    System::{
        Pipes::ImpersonateNamedPipeClient,
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
    },
};

struct OwnedToken(HANDLE);
impl Drop for OwnedToken {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// Reversion cannot be best-effort. If the kernel fails to revert, do not
// continue running an ordinary or privileged thread with ambiguous authority.
struct Impersonation;
impl Drop for Impersonation {
    fn drop(&mut self) {
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

fn typed_information(token: HANDLE, class: i32) -> Result<i32, IdentityDenied> {
    let mut value = 0i32;
    let mut size = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            class,
            (&mut value as *mut i32).cast(),
            size_of::<i32>() as u32,
            &mut size,
        )
    } == 0
        || size != size_of::<i32>() as u32
    {
        return Err(IdentityDenied);
    }
    Ok(value)
}

fn token_user_sid(token: HANDLE) -> Result<Vec<u8>, IdentityDenied> {
    let mut needed = 0u32;
    if unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed) } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || needed < size_of::<TOKEN_USER>() as u32
        || needed > 16_384
    {
        return Err(IdentityDenied);
    }
    let mut words = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let mut used = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            words.as_mut_ptr().cast(),
            needed,
            &mut used,
        )
    } == 0
        || used < size_of::<TOKEN_USER>() as u32
        || used > needed
    {
        return Err(IdentityDenied);
    }
    let user = unsafe { ptr::read_unaligned(words.as_ptr().cast::<TOKEN_USER>()) };
    let base = words.as_ptr() as usize;
    let sid_addr = user.User.Sid as usize;
    if !bounded_buffer_span(base, used as usize, sid_addr, 8, 1) {
        return Err(IdentityDenied);
    }
    let offset = sid_addr - base;
    let bytes = unsafe {
        std::slice::from_raw_parts(
            words.as_ptr().cast::<u8>().add(offset),
            used as usize - offset,
        )
    };
    let count = bounded_sid_bytes(bytes).ok_or(IdentityDenied)?;
    Ok(bytes[..count].to_vec())
}

/// Observe kernel-issued client SID after an actual, successful pipe ReadFile.
/// Never accepts a caller-reported PID/SID or returns a filesystem grant.
/// Synchronous, on the same thread that consumed the pipe request.
pub fn observe_client_sid_after_read(pipe: BorrowedHandle<'_>) -> Result<Vec<u8>, IdentityDenied> {
    let pipe = pipe.as_raw_handle();
    if pipe.is_null() || pipe == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(IdentityDenied);
    }
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(IdentityDenied);
    }
    let _impersonation = Impersonation;
    let mut token = MaybeUninit::<HANDLE>::uninit();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, token.as_mut_ptr()) } == 0 {
        return Err(IdentityDenied);
    }
    let token = OwnedToken(unsafe { token.assume_init() });
    if typed_information(token.0, TokenType)? != TokenImpersonation
        || typed_information(token.0, TokenImpersonationLevel)? < SecurityIdentification
    {
        return Err(IdentityDenied);
    }
    token_user_sid(token.0)
}

/// Test fixture observation of the process token, NOT permission to act
/// as the installed SCM virtual service SID.
pub fn observe_process_sid() -> Result<Vec<u8>, IdentityDenied> {
    let mut token = MaybeUninit::<HANDLE>::uninit();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.as_mut_ptr()) } == 0 {
        return Err(IdentityDenied);
    }
    let token = OwnedToken(unsafe { token.assume_init() });
    token_user_sid(token.0)
}
