//! Experimental handle-only DACL and mandatory-integrity-label preservation.
//! No name-based ACL calls or privilege escalation. Failure denies before
//! cap-tempfile publishes the replacement. Audit SACL, owner/group, alternate
//! streams, and object-origin custody remain outside this nonrelease scope.
use cap_std::fs::File;
use napi::{Error, Result};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorControl, ACL, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    ReOpenFile, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
};

/// Copy only the explicit mandatory integrity label, never the auditing SACL.
/// Windows documents LABEL_SECURITY_INFORMATION as READ_CONTROL to inspect
/// and WRITE_OWNER to set; ordinary callers must not enable SeSecurityPrivilege.
pub(crate) fn copy_existing_integrity_label(existing: &File, replacement: &File) -> Result<()> {
    let mut descriptor = ptr::null_mut();
    let mut label_acl: *mut ACL = ptr::null_mut();
    // SAFETY: GetSecurityInfo returns a descriptor that owns the pointed-to
    // label ACL; no pointer escapes or outlives LocalFree below.
    unsafe {
        let status = GetSecurityInfo(
            existing.as_raw_handle(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut label_acl,
            &mut descriptor,
        );
        if status != 0 {
            if !descriptor.is_null() {
                LocalFree(descriptor);
            }
            return Err(Error::from_reason(format!(
                "Capability integrity-label inspection denied: {}",
                std::io::Error::from_raw_os_error(status as i32).kind(),
            )));
        }
        if descriptor.is_null() {
            return Err(Error::from_reason(
                "Capability integrity-label descriptor unavailable",
            ));
        }
        if label_acl.is_null() {
            // No explicit label on the existing file; do not introduce
            // an unrelated label or try to clear a full audit SACL.
            LocalFree(descriptor);
            return Ok(());
        }
        let handle = ReOpenFile(
            replacement.as_raw_handle(),
            windows_sys::Win32::Storage::FileSystem::WRITE_OWNER | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        );
        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            LocalFree(descriptor);
            return Err(Error::from_reason(format!(
                "Capability integrity-label handle denied: {}",
                std::io::Error::last_os_error().kind(),
            )));
        }
        // SAFETY: ReOpenFile returns a distinct owned HANDLE; File closes it
        // exactly once and the underlying TempFile remains open.
        let label_file = std::fs::File::from_raw_handle(handle);
        let applied = SetSecurityInfo(
            label_file.as_raw_handle(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            label_acl,
        );
        LocalFree(descriptor);
        if applied != 0 {
            return Err(Error::from_reason(format!(
                "Capability integrity-label preservation denied: {}",
                std::io::Error::from_raw_os_error(applied as i32).kind(),
            )));
        }
    }
    Ok(())
}

pub(crate) fn copy_existing_dacl(existing: &File, replacement: &File) -> Result<()> {
    let mut descriptor = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: both Windows handles are live throughout this scope.
    // GetSecurityInfo allocates descriptor and points dacl into its lifetime.
    // All pointers are used before LocalFree and never escape this function.
    unsafe {
        let status = GetSecurityInfo(
            existing.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        );
        if status != 0 {
            if !descriptor.is_null() {
                LocalFree(descriptor);
            }
            return Err(Error::from_reason(format!(
                "Capability DACL inspection denied: {}",
                std::io::Error::from_raw_os_error(status as i32).kind(),
            )));
        }

        // NULL DACL is effectively unrestricted; an object-custody
        // capability cannot safely publish such a permission policy.
        if descriptor.is_null() || dacl.is_null() {
            if !descriptor.is_null() {
                LocalFree(descriptor);
            }
            return Err(Error::from_reason("Capability DACL unavailable"));
        }

        // ReOpenFile requests WRITE_DAC on the SAME file object using its
        // existing live handle, never re-resolving a pathname. The kernel
        // authorizes these rights; failure is an unconditional deny.
        let acl_handle = ReOpenFile(
            replacement.as_raw_handle(),
            WRITE_DAC | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        );
        if acl_handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            LocalFree(descriptor);
            return Err(Error::from_reason(format!(
                "Capability DACL handle denied: {}",
                std::io::Error::last_os_error().kind(),
            )));
        }
        // SAFETY: ReOpenFile returned a new owned handle. std::fs::File closes
        // it exactly once; TempFile retains its independent original handle.
        let acl_file = std::fs::File::from_raw_handle(acl_handle);
        let mut control = 0u16;
        let mut revision = 0u32;
        if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0 {
            LocalFree(descriptor);
            return Err(Error::from_reason(
                "Capability DACL inheritance inspection denied",
            ));
        }
        // Preserve the original inherited/protected DACL policy. Copying the
        // ACE bytes alone would make protected ACLs inherit parent ACEs again.
        let protection = if control & SE_DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        let applied = SetSecurityInfo(
            acl_file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | protection,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        );
        LocalFree(descriptor);
        if applied != 0 {
            return Err(Error::from_reason(format!(
                "Capability DACL preservation denied: {}",
                std::io::Error::from_raw_os_error(applied as i32).kind(),
            )));
        }
    }
    Ok(())
}
