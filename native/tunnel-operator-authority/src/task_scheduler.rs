//! Read-only local Task Scheduler COM principal observation.
//! The registered task definition remains untrusted for *authorization* until
//! installed executable, owner, task ACL and operator-origin gates are proven.
use crate::{compare_current_process_user_sid, ProcessSidEvidence, SidObservationError};
use std::{ffi::c_void, iter, mem, ptr};
use windows::{
    core::BSTR,
    Win32::System::{
        Com::{
            CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
            COINIT_APARTMENTTHREADED,
        },
        TaskScheduler::{ITaskService, TaskScheduler},
        Variant::VARIANT,
    },
};
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER},
    Security::{
        Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
        GetLengthSid, LookupAccountNameW,
    },
};

struct ComApartment;
impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: CoInitializeEx succeeded on this exact calling thread.
        unsafe { CoUninitialize() };
    }
}
fn registered_user_id(task_name: &str) -> Result<String, SidObservationError> {
    // No arbitrary path, hierarchy traversal, or remote Task Scheduler host.
    if task_name.is_empty()
        || task_name.len() > 128
        || !task_name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '-' | '_' | '.'))
        || task_name == "."
        || task_name == ".."
    {
        return Err(SidObservationError::Unverifiable);
    }
    // SAFETY: initialize COM in the current thread; all interfaces are dropped
    // before ComApartment calls CoUninitialize on this same thread.
    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
        .ok()
        .map_err(|_| SidObservationError::Unverifiable)?;
    let _apartment = ComApartment;
    // SAFETY: local in-process COM activation, no remote server supplied.
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
            .map_err(|_| SidObservationError::Unverifiable)?;
    let empty = VARIANT::default();
    // SAFETY: empty variants instruct the official service to use the local host.
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }
        .map_err(|_| SidObservationError::Unverifiable)?;
    let root = unsafe { service.GetFolder(&BSTR::from("\\")) }
        .map_err(|_| SidObservationError::Unverifiable)?;
    let task = unsafe { root.GetTask(&BSTR::from(task_name)) }
        .map_err(|_| SidObservationError::Unverifiable)?;
    let definition = unsafe { task.Definition() }.map_err(|_| SidObservationError::Unverifiable)?;
    let principal =
        unsafe { definition.Principal() }.map_err(|_| SidObservationError::Unverifiable)?;
    let mut user = BSTR::new();
    // SAFETY: the official COM interface initializes the output BSTR and
    // its wrapper releases the allocation when dropped.
    unsafe { principal.UserId(&mut user) }.map_err(|_| SidObservationError::Unverifiable)?;
    let name = user.to_string();
    if name.is_empty() || name.len() > 512 || name.contains('\0') {
        return Err(SidObservationError::Unverifiable);
    }
    Ok(name)
}

struct OwnedLocalAllocation(*mut c_void);
impl Drop for OwnedLocalAllocation {
    fn drop(&mut self) {
        // SAFETY: SID conversion APIs return LocalFree-owned allocations.
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn resolve_registered_user_sid(name: &str) -> Result<Vec<u8>, SidObservationError> {
    // Task Scheduler COM commonly returns a canonical SID string rather than
    // DOMAIN\\username. LookupAccountNameW does not resolve SID strings.
    // Only the numeric Windows SID spelling is accepted in this branch.
    if let Some(components) = name.strip_prefix("S-") {
        if name.len() > 184
            || !name.starts_with("S-1-")
            || !components
                .bytes()
                .all(|byte| byte == b'-' || byte.is_ascii_digit())
        {
            return Err(SidObservationError::Unverifiable);
        }
        let wide: Vec<u16> = name.encode_utf16().chain(iter::once(0)).collect();
        let mut owned_sid: *mut c_void = ptr::null_mut();
        // SAFETY: input is a bounded UTF-16 NUL-terminated numeric SID; the
        // documented Win32 API allocates a SID that the guard releases.
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut owned_sid) } == 0
            || owned_sid.is_null()
        {
            return Err(SidObservationError::Unverifiable);
        }
        let sid = OwnedLocalAllocation(owned_sid);
        // A valid parse alone is insufficient: Win32 may coerce an out-of-range
        // subauthority. Require byte-for-byte canonical string round-trip.
        let mut canonical_ptr: *mut u16 = ptr::null_mut();
        // SAFETY: sid.0 is the live validated OS SID from the preceding API.
        if unsafe { ConvertSidToStringSidW(sid.0, &mut canonical_ptr) } == 0
            || canonical_ptr.is_null()
        {
            return Err(SidObservationError::Unverifiable);
        }
        let _canonical = OwnedLocalAllocation(canonical_ptr.cast());
        let mut canonical_len = 0usize;
        // SAFETY: the Win32 API returns an allocated NUL-terminated UTF-16
        // string. Scan only up to the bounded input length plus terminator.
        while canonical_len <= name.len() && unsafe { *canonical_ptr.add(canonical_len) } != 0 {
            canonical_len += 1;
        }
        if canonical_len != name.len()
            || unsafe { std::slice::from_raw_parts(canonical_ptr, canonical_len) }
                != &wide[..wide.len() - 1]
        {
            return Err(SidObservationError::Unverifiable);
        }
        let length = unsafe { GetLengthSid(sid.0) } as usize;
        if !(12..=256).contains(&length) {
            return Err(SidObservationError::Unverifiable);
        }
        // SAFETY: GetLengthSid queries the valid API-allocated SID before
        // returning a bounded copy; the allocation remains owned throughout.
        let bytes = unsafe { std::slice::from_raw_parts(sid.0.cast::<u8>(), length) };
        if !crate::windows::valid_sid_bytes(bytes) {
            return Err(SidObservationError::Unverifiable);
        }
        return Ok(bytes.to_vec());
    }
    let wide: Vec<u16> = name.encode_utf16().chain(iter::once(0)).collect();
    let (mut sid_bytes, mut domain_chars, mut use_type) = (0u32, 0u32, 0i32);
    // SAFETY: query required buffer sizes using the local account database.
    let first = unsafe {
        LookupAccountNameW(
            ptr::null(),
            wide.as_ptr(),
            ptr::null_mut(),
            &mut sid_bytes,
            ptr::null_mut(),
            &mut domain_chars,
            &mut use_type,
        )
    };
    if first != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || sid_bytes == 0
        || sid_bytes > 256
        || domain_chars > 256
    {
        return Err(SidObservationError::Unverifiable);
    }
    let sid_capacity = sid_bytes;
    let mut words = vec![0usize; (sid_bytes as usize).div_ceil(mem::size_of::<usize>())];
    let mut domain = vec![0u16; (domain_chars as usize).max(1)];
    // SAFETY: OS writes within allocated SID and domain buffers.
    let ok = unsafe {
        LookupAccountNameW(
            ptr::null(),
            wide.as_ptr(),
            words.as_mut_ptr().cast(),
            &mut sid_bytes,
            domain.as_mut_ptr(),
            &mut domain_chars,
            &mut use_type,
        )
    };
    if ok == 0 || sid_bytes == 0 || sid_bytes > sid_capacity {
        return Err(SidObservationError::Unverifiable);
    }
    // SAFETY: sid_bytes is now bounded by the owned aligned allocation.
    let sid =
        unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), sid_bytes as usize) };
    if !crate::windows::valid_sid_bytes(sid) {
        return Err(SidObservationError::Unverifiable);
    }
    Ok(sid.to_vec())
}

pub(super) fn compare_registered_task_principal(
    task_name: &str,
) -> Result<ProcessSidEvidence, SidObservationError> {
    let registered_user = registered_user_id(task_name)?;
    // The principal comes from local Task Scheduler COM, not CLI/env/XML input.
    // Resolve either canonical SID or account name through native Windows APIs.
    // SID equality remains read-only evidence, never operator authorization.
    let sid = resolve_registered_user_sid(&registered_user)?;
    compare_current_process_user_sid(&sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_principal_sid_string_resolves_to_kernel_token_identity() {
        // Task Scheduler commonly returns canonical S-1-... identities rather
        // than DOMAIN\\name. This test never alters registered tasks.
        let current = crate::observe_current_process_user_sid().expect("real TokenUser");
        let authority = current[2..8]
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        let mut text = format!("S-{}-{authority}", current[0]);
        for part in current[8..].chunks_exact(4) {
            let subauthority = u32::from_le_bytes(part.try_into().expect("four bytes"));
            text.push_str(&format!("-{subauthority}"));
        }
        assert_eq!(
            resolve_registered_user_sid(&text).expect("Task Scheduler SID principal"),
            current,
            "canonical Task Scheduler SID must match real TokenUser without name lookup"
        );
    }

    #[test]
    fn well_known_sid_string_resolves_to_canonical_binary_sid() {
        assert_eq!(
            resolve_registered_user_sid("S-1-5-18"),
            Ok(vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0])
        );
    }

    #[test]
    fn malformed_sid_strings_fail_closed() {
        let oversized = "S-1-5-18".repeat(30);
        for value in [
            "S-1-",
            "S-1-5-18-extra",
            "S-1-5-18\\Other",
            "S-1-5-18\0Injected",
            "S-1-5-4294967296",
            oversized.as_str(),
        ] {
            assert_eq!(
                resolve_registered_user_sid(value),
                Err(SidObservationError::Unverifiable),
                "unsafe SID representation must be rejected"
            );
        }
    }
}
