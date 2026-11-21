//! Windows kernel process DACL hardening for a *future* protected launcher.
//! This does NOT identify the original MCP host, issue authority, or grant
//! filesystem I/O. The future issuer must hold a trusted process handle and
//! apply this while its child is suspended, before untrusted code can run.
//! Privileged administrator / SeDebug / SeRestore attackers are out of scope.
use crate::IdentityDenied;
use std::{
    ffi::c_void,
    os::windows::io::{AsRawHandle, BorrowedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, HANDLE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_KERNEL_OBJECT,
        },
        SetKernelObjectSecurity, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
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

fn checked_sid_text(sid: *mut c_void) -> Result<String, IdentityDenied> {
    if sid.is_null() {
        return Err(IdentityDenied);
    }
    let mut text: *mut u16 = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err(IdentityDenied);
    }
    let _allocation = LocalAllocation(text.cast());
    let length = (0..192)
        .find(|&i| unsafe { *text.add(i) == 0 })
        .ok_or(IdentityDenied)?;
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| IdentityDenied)
}

/// Replace a trusted, newly-created client process's DACL with limited rights
/// for its OS-observed owner. It must be called *before child execution*.
/// No caller-supplied SID or identity claims are accepted. A process can still
/// be impersonated by its own executing code or a privileged OS administrator.
pub fn seal_process_owner_rights(process: BorrowedHandle<'_>) -> Result<(), IdentityDenied> {
    let handle = process.as_raw_handle() as HANDLE;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(IdentityDenied);
    }
    let mut owner = ptr::null_mut();
    let mut current_descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut current_descriptor,
        )
    };
    let _current = LocalAllocation(current_descriptor);
    if status != 0 || current_descriptor.is_null() {
        return Err(IdentityDenied);
    }
    let owner_text = checked_sid_text(owner)?;

    // OWNER RIGHTS is S-1-3-4. Its explicit ACE suppresses implicit
    // READ_CONTROL/WRITE_DAC owner grants. Do not allow the same-SID peer to
    // rewrite this ACL and reopen PROCESS_DUP_HANDLE on a trusted client.
    // SYSTEM retains custody. Owner gets only READ_CONTROL/limited query.
    let sddl = format!("D:P(A;;GA;;;SY)(A;;0x21000;;;{owner_text})(A;;RC;;;OW)");
    let utf16: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut protected_descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            utf16.as_ptr(),
            1,
            &mut protected_descriptor,
            ptr::null_mut(),
        )
    } == 0
        || protected_descriptor.is_null()
    {
        return Err(IdentityDenied);
    }
    let _protected = LocalAllocation(protected_descriptor);
    if unsafe { SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, protected_descriptor) }
        == 0
    {
        return Err(IdentityDenied);
    }
    Ok(())
}
