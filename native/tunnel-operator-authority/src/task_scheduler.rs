//! Read-only local Task Scheduler COM principal observation.
//! The registered task definition remains untrusted for *authorization* until
//! installed executable, owner, task ACL and operator-origin gates are proven.
use crate::{compare_current_process_user_sid, ProcessSidEvidence, SidObservationError};
use std::{iter, mem, ptr};
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
    Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER},
    Security::LookupAccountNameW,
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

fn resolve_account_name_sid(name: &str) -> Result<Vec<u8>, SidObservationError> {
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
    // The account name comes from Task Scheduler COM, never CLI/env/XML input.
    // Resolve it through Windows account APIs rather than string comparison.
    let sid = resolve_account_name_sid(&registered_user)?;
    compare_current_process_user_sid(&sid)
}
