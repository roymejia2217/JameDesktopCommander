//! Non-shipping Windows process/thread DACLs supplied at CreateProcessW time.
//! Post-creation sealing alone has an unavoidable process/thread-open race.
//! A protected issuer must supply the independently controlled primary token
//! and retain these allocations through CreateProcessAsUserW/CreateProcessW.
//! This API is NOT a trusted launcher, process-origin grant or broker.
use crate::{
    token_policy::{bounded_buffer_span, bounded_sid_bytes},
    IdentityDenied,
};
use std::{
    ffi::c_void,
    mem::size_of,
    os::windows::io::{AsRawHandle, BorrowedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        GetTokenInformation, TokenOwner, TokenPrimary, TokenType, SECURITY_ATTRIBUTES, TOKEN_OWNER,
    },
};
struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Owns both kernel object security descriptors. Clients receive only a
/// Rust-lifetime-bound borrowed view for the CreateProcessW call; descriptor
/// pointers must never be published to the MCP client or detached from
/// their owning allocation.
pub struct OwnerRightsCreationDescriptors {
    process: LocalAllocation,
    primary_thread: LocalAllocation,
}

/// Win32 creation attributes tied to their owning security descriptors.
/// Safe Rust cannot retain this view after its owner is dropped. Never
/// clone the underlying raw SECURITY_ATTRIBUTES into a longer-lived object.
pub struct BorrowedCreationAttributes<'a> {
    process: SECURITY_ATTRIBUTES,
    primary_thread: SECURITY_ATTRIBUTES,
    _owner: &'a OwnerRightsCreationDescriptors,
}
impl BorrowedCreationAttributes<'_> {
    pub fn process(&self) -> &SECURITY_ATTRIBUTES {
        &self.process
    }
    pub fn primary_thread(&self) -> &SECURITY_ATTRIBUTES {
        &self.primary_thread
    }
}
impl OwnerRightsCreationDescriptors {
    /// Caller must hold the *real* primary token intended for its new child.
    /// The token owner is obtained from the kernel, not client-supplied SID
    /// text. Token provenance and a protected launcher remain external gates.
    pub fn from_primary_token(token: BorrowedHandle<'_>) -> Result<Self, IdentityDenied> {
        let token = token.as_raw_handle() as HANDLE;
        let mut kind = 0i32;
        let mut used = 0u32;
        if unsafe {
            GetTokenInformation(
                token,
                TokenType,
                (&mut kind as *mut i32).cast(),
                size_of::<i32>() as u32,
                &mut used,
            )
        } == 0
            || used != size_of::<i32>() as u32
            || kind != TokenPrimary
        {
            return Err(IdentityDenied);
        }
        let owner = primary_token_owner_sid_text(token)?;
        Ok(Self {
            process: descriptor(&owner, "0x21000")?,
            primary_thread: descriptor(&owner, "RC")?,
        })
    }
    /// Returns attributes whose lifetime is bounded by the owner of
    /// both descriptors. Keep this borrowed view alive through CreateProcess.
    pub fn borrow_attributes(&self) -> BorrowedCreationAttributes<'_> {
        BorrowedCreationAttributes {
            process: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.process.0,
                bInheritHandle: 0,
            },
            primary_thread: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.primary_thread.0,
                bInheritHandle: 0,
            },
            _owner: self,
        }
    }
}

fn primary_token_owner_sid_text(token: HANDLE) -> Result<String, IdentityDenied> {
    let mut needed = 0u32;
    if unsafe { GetTokenInformation(token, TokenOwner, ptr::null_mut(), 0, &mut needed) } != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || needed < size_of::<TOKEN_OWNER>() as u32
        || needed > 4096
    {
        return Err(IdentityDenied);
    }
    let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let mut used = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            TokenOwner,
            storage.as_mut_ptr().cast(),
            needed,
            &mut used,
        )
    } == 0
        || used < size_of::<TOKEN_OWNER>() as u32
        || used > needed
    {
        return Err(IdentityDenied);
    }
    let token_owner = unsafe { ptr::read_unaligned(storage.as_ptr().cast::<TOKEN_OWNER>()) };
    let base = storage.as_ptr() as usize;
    let sid_addr = token_owner.Owner as usize;
    if !bounded_buffer_span(base, used as usize, sid_addr, 8, 1) {
        return Err(IdentityDenied);
    }
    let offset = sid_addr - base;
    let slice = unsafe {
        std::slice::from_raw_parts(
            storage.as_ptr().cast::<u8>().add(offset),
            used as usize - offset,
        )
    };
    if bounded_sid_bytes(slice).is_none() {
        return Err(IdentityDenied);
    }
    let mut sid_text: *mut u16 = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(token_owner.Owner, &mut sid_text) } == 0
        || sid_text.is_null()
    {
        return Err(IdentityDenied);
    }
    let _sid_text_buffer = LocalAllocation(sid_text.cast());
    let length = (0..192)
        .find(|&i| unsafe { *sid_text.add(i) } == 0)
        .ok_or(IdentityDenied)?;
    String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, length) })
        .map_err(|_| IdentityDenied)
}
fn descriptor(owner: &str, owner_permissions: &str) -> Result<LocalAllocation, IdentityDenied> {
    // OWNER RIGHTS (S-1-3-4) prevents implicit owner WRITE_DAC/READ_CONTROL.
    // Explicit SYSTEM control remains; neither child object grants
    // PROCESS_DUP_HANDLE nor THREAD_SET_CONTEXT to the token owner.
    let sddl = format!("D:P(A;;GA;;;SY)(A;;{owner_permissions};;;{owner})(A;;RC;;;OW)");
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut raw = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            1,
            &mut raw,
            ptr::null_mut(),
        )
    } == 0
        || raw.is_null()
    {
        return Err(IdentityDenied);
    }
    Ok(LocalAllocation(raw))
}
