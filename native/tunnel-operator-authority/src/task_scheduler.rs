//! Read-only local Task Scheduler COM principal observation.
//! The registered task definition remains untrusted for *authorization* until
//! installed executable, owner, task ACL and operator-origin gates are proven.
use crate::{
    compare_current_process_user_sid, ProcessSidEvidence, SidObservationError, TaskOwnerEvidence,
};
use std::{ffi::c_void, iter, mem, ptr};
use windows::{
    core::BSTR,
    Win32::System::{
        Com::{
            CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
            COINIT_APARTMENTTHREADED,
        },
        TaskScheduler::{IRegisteredTask, ITaskService, TaskScheduler},
        Variant::VARIANT,
    },
};
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            ConvertStringSidToSidW,
        },
        GetLengthSid, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidAcl,
        IsValidSecurityDescriptor, IsValidSid, IsWellKnownSid, LookupAccountNameW,
        WinBuiltinAdministratorsSid, ACL,
    },
};

struct ComApartment;
impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: CoInitializeEx succeeded on this exact calling thread.
        unsafe { CoUninitialize() };
    }
}
// Both synchronous observers return owned results before the COM apartment
// ends. Share the same local-only name validation, routing and cleanup.
fn with_registered_task<T>(
    task_name: &str,
    read: impl FnOnce(&IRegisteredTask) -> Result<T, SidObservationError>,
) -> Result<T, SidObservationError> {
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
    // SAFETY: initialize COM in this thread. Live interfaces are dropped
    // before ComApartment calls CoUninitialize on this same thread.
    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
        .ok()
        .map_err(|_| SidObservationError::Unverifiable)?;
    let _apartment = ComApartment;
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
            .map_err(|_| SidObservationError::Unverifiable)?;
    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }
        .map_err(|_| SidObservationError::Unverifiable)?;
    let root = unsafe { service.GetFolder(&BSTR::from("\\")) }
        .map_err(|_| SidObservationError::Unverifiable)?;
    let task = unsafe { root.GetTask(&BSTR::from(task_name)) }
        .map_err(|_| SidObservationError::Unverifiable)?;
    read(&task)
}

fn registered_user_id(task_name: &str) -> Result<String, SidObservationError> {
    with_registered_task(task_name, |task| {
        let definition =
            unsafe { task.Definition() }.map_err(|_| SidObservationError::Unverifiable)?;
        let principal =
            unsafe { definition.Principal() }.map_err(|_| SidObservationError::Unverifiable)?;
        let mut user = BSTR::new();
        unsafe { principal.UserId(&mut user) }.map_err(|_| SidObservationError::Unverifiable)?;
        let name = user.to_string();
        if name.is_empty() || name.len() > 512 || name.contains('\0') {
            return Err(SidObservationError::Unverifiable);
        }
        Ok(name)
    })
}

struct OwnedLocalAllocation(*mut c_void);
impl Drop for OwnedLocalAllocation {
    fn drop(&mut self) {
        // SAFETY: Windows allocations returned by the conversion APIs use LocalFree.
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

// One owned, bounded self-relative descriptor for all read-only task probes.
struct ValidatedTaskDescriptor {
    allocation: OwnedLocalAllocation,
    bytes: usize,
}
impl ValidatedTaskDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, SidObservationError> {
        if sddl.is_empty() || sddl.len() > 16384 || sddl.contains('\0') {
            return Err(SidObservationError::Unverifiable);
        }
        let wide: Vec<u16> = sddl.encode_utf16().chain(iter::once(0)).collect();
        let mut ptr: *mut c_void = ptr::null_mut();
        let mut size = 0u32;
        // SAFETY: Windows validates SDDL and owns the allocated self-relative SD.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut ptr,
                &mut size,
            )
        };
        let allocation = OwnedLocalAllocation(ptr);
        if ok == 0
            || ptr.is_null()
            || !(20..=32768).contains(&size)
            || unsafe { IsValidSecurityDescriptor(ptr) } == 0
        {
            return Err(SidObservationError::Unverifiable);
        }
        Ok(Self {
            allocation,
            bytes: size as usize,
        })
    }
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: the OS-sized allocation remains owned for this borrow.
        unsafe { std::slice::from_raw_parts(self.allocation.0.cast(), self.bytes) }
    }
}

// Classify *owner identity only* from a native-validated SDDL descriptor.
// A valid ACL can still grant access to untrusted principals. This is never
// sufficient for task custody, authorization, or install provenance.
fn classify_task_owner_sddl(sddl: &str) -> Result<TaskOwnerEvidence, SidObservationError> {
    let _owned = ValidatedTaskDescriptor::from_sddl(sddl)?;
    let descriptor = _owned.allocation.0;
    let mut owner: *mut c_void = ptr::null_mut();
    let mut owner_defaulted = 0i32;
    let mut dacl_present = 0i32;
    let mut dacl_defaulted = 0i32;
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: Both API calls examine fields of the same live validated SD;
    // the SID and ACL pointers remain borrowed until _owned drops.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || unsafe {
            GetSecurityDescriptorDacl(
                descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
        } == 0
        || dacl_present == 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(SidObservationError::Unverifiable);
    }
    if unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) } != 0 {
        return Ok(TaskOwnerEvidence::BuiltinAdministrators);
    }
    let owner_len = unsafe { GetLengthSid(owner) } as usize;
    if !(12..=256).contains(&owner_len) {
        return Err(SidObservationError::Unverifiable);
    }
    // SAFETY: IsValidSid succeeded and GetLengthSid is bounded; the owner
    // remains allocated with the security descriptor until this scope exits.
    let owner_bytes = unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), owner_len) };
    if !crate::windows::valid_sid_bytes(owner_bytes) {
        return Err(SidObservationError::Unverifiable);
    }
    Ok(match compare_current_process_user_sid(owner_bytes)? {
        ProcessSidEvidence::SameAccount => TaskOwnerEvidence::CurrentUser,
        ProcessSidEvidence::DifferentAccount => TaskOwnerEvidence::DifferentOwner,
    })
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

/// Reads actual registered task owner + non-null DACL evidence through COM.
/// Same user/group ownership is not proof of a JDC-controlled registration.
pub(super) fn observe_registered_task_owner(
    task_name: &str,
) -> Result<TaskOwnerEvidence, SidObservationError> {
    with_registered_task(task_name, |task| {
        // OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION = 0x5.
        // Read only: no Group/SACL query, elevation or task registration.
        let sddl = unsafe { task.GetSecurityDescriptor(5) }
            .map_err(|_| SidObservationError::Unverifiable)?;
        classify_task_owner_sddl(&sddl.to_string())
    })
}

/// Conservative structure check: this is not effective rights evaluation.
fn classify_task_acl_sddl(sddl: &str) -> Result<crate::TaskAclEvidence, SidObservationError> {
    let descriptor = ValidatedTaskDescriptor::from_sddl(sddl)?;
    let token_user = crate::observe_current_process_user_sid()?;
    // Fixed Windows well-known SID strings are resolved by native APIs.
    let system = resolve_registered_user_sid("S-1-5-18")?;
    let administrators = resolve_registered_user_sid("S-1-5-32-544")?;
    if !crate::relative_sd::private_acl(
        descriptor.as_bytes(),
        &token_user,
        &system,
        &administrators,
    ) {
        return Err(SidObservationError::Unverifiable);
    }
    Ok(crate::TaskAclEvidence::AllowlistedPrincipalsOnly)
}

pub(super) fn observe_registered_task_acl(
    task_name: &str,
) -> Result<crate::TaskAclEvidence, SidObservationError> {
    with_registered_task(task_name, |task| {
        // OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION. Read-only.
        let sddl = unsafe { task.GetSecurityDescriptor(5) }
            .map_err(|_| SidObservationError::Unverifiable)?;
        classify_task_acl_sddl(&sddl.to_string())
    })
}

// This lexical check rejects task-provided UNC, device namespace, environment,
// traversal and ADS spellings. It is deliberately NOT file-object validation.
fn untrusted_local_drive_path(raw: &str) -> Result<std::path::PathBuf, SidObservationError> {
    let bytes = raw.as_bytes();
    if bytes.len() < 4
        || bytes.len() > 4096
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || raw[3..]
            .split('\\')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || raw[3..].contains(':')
        || raw.chars().any(|c| c.is_control() || c == '%' || c == '"')
    {
        return Err(SidObservationError::Unverifiable);
    }
    let path = std::path::PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(SidObservationError::Unverifiable);
    }
    Ok(path)
}

fn observe_single_exec_action(
    actions: &windows::Win32::System::TaskScheduler::IActionCollection,
) -> Result<crate::UntrustedRegisteredExecObservation, SidObservationError> {
    use windows::{
        core::Interface,
        Win32::System::TaskScheduler::{IExecAction, TASK_ACTION_EXEC, TASK_ACTION_TYPE},
    };
    let mut count = 0i32;
    unsafe { actions.Count(&mut count) }.map_err(|_| SidObservationError::Unverifiable)?;
    if count != 1 {
        return Err(SidObservationError::Unverifiable);
    }
    // Task Scheduler's IActionCollection is one-based.
    let action = unsafe { actions.get_Item(1) }.map_err(|_| SidObservationError::Unverifiable)?;
    let mut kind = TASK_ACTION_TYPE(-1);
    unsafe { action.Type(&mut kind) }.map_err(|_| SidObservationError::Unverifiable)?;
    if kind != TASK_ACTION_EXEC {
        return Err(SidObservationError::Unverifiable);
    }
    let exec: IExecAction = action
        .cast()
        .map_err(|_| SidObservationError::Unverifiable)?;
    let (mut path, mut args, mut directory) = (BSTR::new(), BSTR::new(), BSTR::new());
    unsafe { exec.Path(&mut path) }.map_err(|_| SidObservationError::Unverifiable)?;
    unsafe { exec.Arguments(&mut args) }.map_err(|_| SidObservationError::Unverifiable)?;
    unsafe { exec.WorkingDirectory(&mut directory) }
        .map_err(|_| SidObservationError::Unverifiable)?;
    // Bound untrusted COM BSTR data before UTF-16 conversion and allocation.
    if path.len() > 4096 || args.len() > 8192 || directory.len() > 4096 {
        return Err(SidObservationError::Unverifiable);
    }
    // Strict UTF-16: do not silently coerce an unpaired surrogate to U+FFFD.
    let path = String::from_utf16(&path).map_err(|_| SidObservationError::Unverifiable)?;
    let args = String::from_utf16(&args).map_err(|_| SidObservationError::Unverifiable)?;
    let directory =
        String::from_utf16(&directory).map_err(|_| SidObservationError::Unverifiable)?;
    if args.len() > 8192 || args.chars().any(char::is_control) {
        return Err(SidObservationError::Unverifiable);
    }
    let working_directory = if directory.is_empty() {
        None
    } else {
        Some(untrusted_local_drive_path(&directory)?)
    };
    Ok(crate::UntrustedRegisteredExecObservation {
        executable: untrusted_local_drive_path(&path)?,
        arguments: args,
        working_directory,
    })
}

/// OS-local COM observation, not publisher, installer, rights or client proof.
/// Never pass executable directly to a process-launch API.
pub(super) fn observe_registered_exec_action(
    task_name: &str,
) -> Result<crate::UntrustedRegisteredExecObservation, SidObservationError> {
    with_registered_task(task_name, |task| {
        let definition =
            unsafe { task.Definition() }.map_err(|_| SidObservationError::Unverifiable)?;
        let actions =
            unsafe { definition.Actions() }.map_err(|_| SidObservationError::Unverifiable)?;
        observe_single_exec_action(&actions)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::Interface;
    use windows::Win32::System::TaskScheduler::{
        IActionCollection, IExecAction, TASK_ACTION_COM_HANDLER, TASK_ACTION_EXEC,
    };

    // In-memory task definitions only: no RegisterTaskDefinition, no mutation
    // of any real scheduled task, service, credential or installed binary.
    fn with_fixture_actions<T>(test: impl FnOnce(&IActionCollection) -> T) -> T {
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
            .ok()
            .expect("fixture COM apartment");
        let _apartment = ComApartment;
        let service: ITaskService =
            unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
                .expect("fixture COM service");
        let empty = VARIANT::default();
        unsafe { service.Connect(&empty, &empty, &empty, &empty) }.expect("connect local fixture");
        let definition =
            unsafe { service.NewTask(0) }.expect("unregistered in-memory task definition");
        let actions = unsafe { definition.Actions() }.expect("new task action collection");
        test(&actions)
    }

    fn add_exec(actions: &IActionCollection, executable: &str) {
        let action = unsafe { actions.Create(TASK_ACTION_EXEC) }.expect("fixture Exec action");
        let exec: IExecAction = action.cast().expect("IExecAction");
        unsafe { exec.SetPath(&BSTR::from(executable)) }.expect("set in-memory fixture path");
        unsafe { exec.SetArguments(&BSTR::from("run --profile fixture")) }
            .expect("set in-memory fixture arguments");
    }

    #[test]
    fn in_memory_com_exec_action_is_observed_as_untrusted_data() {
        with_fixture_actions(|actions| {
            add_exec(actions, r"C:\Program Files\OpenAI\tunnel-client.exe");
            let evidence =
                observe_single_exec_action(actions).expect("one Exec action should be observable");
            assert_eq!(
                evidence.executable,
                std::path::PathBuf::from(r"C:\Program Files\OpenAI\tunnel-client.exe")
            );
            assert_eq!(evidence.arguments, "run --profile fixture");
            assert_eq!(evidence.working_directory, None);
        });
    }

    #[test]
    fn in_memory_com_rejects_zero_extra_or_non_exec_actions() {
        with_fixture_actions(|actions| {
            assert_eq!(
                observe_single_exec_action(actions),
                Err(SidObservationError::Unverifiable)
            );
            add_exec(actions, r"C:\Program Files\OpenAI\tunnel-client.exe");
            assert!(observe_single_exec_action(actions).is_ok());
            unsafe { actions.Create(TASK_ACTION_COM_HANDLER) }.expect("COM handler fixture");
            assert_eq!(
                observe_single_exec_action(actions),
                Err(SidObservationError::Unverifiable)
            );
        });
        with_fixture_actions(|actions| {
            add_exec(actions, r"C:\One\a.exe");
            add_exec(actions, r"C:\Two\b.exe");
            assert_eq!(
                observe_single_exec_action(actions),
                Err(SidObservationError::Unverifiable)
            );
        });
        with_fixture_actions(|actions| {
            unsafe { actions.Create(TASK_ACTION_COM_HANDLER) }.expect("COM-only fixture");
            assert_eq!(
                observe_single_exec_action(actions),
                Err(SidObservationError::Unverifiable)
            );
        });
    }

    #[test]
    fn in_memory_com_preserves_independent_working_directory() {
        with_fixture_actions(|actions| {
            let action = unsafe { actions.Create(TASK_ACTION_EXEC) }.expect("Exec");
            let exec: IExecAction = action.cast().expect("Exec interface");
            unsafe { exec.SetPath(&BSTR::from(r"C:\Tools\node.exe")) }.expect("path");
            unsafe { exec.SetWorkingDirectory(&BSTR::from(r"D:\JDC\Runtime")) }
                .expect("different trusted-by-nobody working directory");
            let observed = observe_single_exec_action(actions).expect("valid shape");
            assert_eq!(
                observed.working_directory,
                Some(std::path::PathBuf::from(r"D:\JDC\Runtime"))
            );
        });
        with_fixture_actions(|actions| {
            let action = unsafe { actions.Create(TASK_ACTION_EXEC) }.expect("Exec");
            let exec: IExecAction = action.cast().expect("Exec interface");
            unsafe { exec.SetPath(&BSTR::from(r"C:\Tools\node.exe")) }.expect("path");
            unsafe { exec.SetWorkingDirectory(&BSTR::from(r"..\relative")) }
                .expect("in-memory task permits relative path until registration");
            assert_eq!(
                observe_single_exec_action(actions),
                Err(SidObservationError::Unverifiable)
            );
        });
    }

    #[test]
    fn in_memory_com_rejects_untrusted_control_arguments() {
        with_fixture_actions(|actions| {
            let action = unsafe { actions.Create(TASK_ACTION_EXEC) }.expect("Exec");
            let exec: IExecAction = action.cast().expect("Exec interface");
            unsafe { exec.SetPath(&BSTR::from(r"C:\Tools\node.exe")) }.expect("path");
            unsafe { exec.SetArguments(&BSTR::from("run\nsecond")) }.expect("in-memory args");
            assert_eq!(
                observe_single_exec_action(actions),
                Err(SidObservationError::Unverifiable)
            );
        });
    }

    #[test]
    fn in_memory_com_rejects_oversized_arguments_before_utf16_copy() {
        with_fixture_actions(|actions| {
            let action = unsafe { actions.Create(TASK_ACTION_EXEC) }.expect("Exec");
            let exec: IExecAction = action.cast().expect("Exec interface");
            unsafe { exec.SetPath(&BSTR::from(r"C:\Tools\node.exe")) }.expect("path");
            let excessive = "x".repeat(8193);
            unsafe { exec.SetArguments(&BSTR::from(excessive.as_str())) }
                .expect("in-memory oversized command");
            assert_eq!(
                observe_single_exec_action(actions),
                Err(SidObservationError::Unverifiable)
            );
        });
    }

    #[test]
    fn in_memory_com_rejects_invalid_exec_paths() {
        for bad in [
            "relative.exe",
            r"\\remote\share\untrusted.exe",
            r"C:\temp\..\other.exe",
            r"C:\bad\evil.exe:ads",
            r"\\?\C:\extended.exe",
            "",
        ] {
            with_fixture_actions(|actions| {
                add_exec(actions, bad);
                assert_eq!(
                    observe_single_exec_action(actions),
                    Err(SidObservationError::Unverifiable),
                    "untrusted path shape must be rejected"
                );
            });
        }
    }

    #[test]
    fn private_task_acl_requires_only_owner_system_or_administrators() {
        assert_eq!(
            classify_task_acl_sddl("O:BAG:BAD:(A;;FA;;;BA)(A;;FR;;;SY)"),
            Ok(crate::TaskAclEvidence::AllowlistedPrincipalsOnly),
        );
    }

    #[test]
    fn broad_task_acl_grants_are_not_reported_as_private() {
        for sddl in [
            "O:BAG:BAD:(A;;FA;;;WD)",
            "O:BAG:BAD:(A;;FR;;;BU)",
            "O:BAG:BAD:(A;;FA;;;BA)(A;;FR;;;AU)",
            "O:BAG:BAD:(A;;FA;;;BA)(A;;FA;;;WD)",
        ] {
            assert_eq!(
                classify_task_acl_sddl(sddl),
                Err(SidObservationError::Unverifiable)
            );
        }
    }

    #[test]
    fn incomplete_task_acl_is_never_observed_as_private() {
        for sddl in [
            "",
            "O:BA",
            "O:BAG:BAD:NO_ACCESS_CONTROL",
            "O:BAG:BAD:(A;;FA;;;WD",
            "not-a-sddl",
        ] {
            assert_eq!(
                classify_task_acl_sddl(sddl),
                Err(SidObservationError::Unverifiable)
            );
        }
    }

    #[test]
    fn registered_task_owner_is_distinct_from_execution_principal() {
        // BUILTIN\\Administrators owns a real-world S4U user task.
        assert_eq!(
            classify_task_owner_sddl("O:BAG:BAD:(A;;FA;;;BA)"),
            Ok(crate::TaskOwnerEvidence::BuiltinAdministrators)
        );
        // The DACL granting administrators access does not change SYSTEM ownership.
        assert_eq!(
            classify_task_owner_sddl("O:SYG:SYD:(A;;FA;;;BA)"),
            Ok(crate::TaskOwnerEvidence::DifferentOwner)
        );
    }

    #[test]
    fn current_token_owner_is_not_confused_with_builtin_admins() {
        let current = crate::observe_current_process_user_sid().expect("real TokenUser");
        let authority = current[2..8]
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        let mut sid_text = format!("S-{}-{authority}", current[0]);
        for part in current[8..].chunks_exact(4) {
            sid_text.push_str(&format!(
                "-{}",
                u32::from_le_bytes(part.try_into().expect("four SID bytes"))
            ));
        }
        let sddl = format!("O:{sid_text}G:BAD:(A;;FA;;;BA)");
        assert_eq!(
            classify_task_owner_sddl(&sddl),
            Ok(TaskOwnerEvidence::CurrentUser)
        );
    }

    #[test]
    fn task_owner_observation_fails_closed_on_missing_or_invalid_dacl() {
        for descriptor in [
            "O:BA",
            "O:BAG:BA",
            "O:BAG:BAD:NO_ACCESS_CONTROL",
            "not-a-sddl",
            "",
        ] {
            assert_eq!(
                classify_task_owner_sddl(descriptor),
                Err(SidObservationError::Unverifiable),
                "incomplete security descriptor must not yield owner evidence"
            );
        }
    }

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
