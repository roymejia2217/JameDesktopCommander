//! Read-only Windows kernel identity evidence for issue #270.
//!
//! TokenUser is account identity, **not** proof of a local interactive
//! operator. A remote MCP worker may have the same SID. No observation here
//! authorizes service control, filesystem writes, or credential rotation.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidObservationError {
    Unverifiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSidEvidence {
    SameAccount,
    DifferentAccount,
}

#[cfg(windows)]
mod windows;

/// Copies a validated kernel-issued TokenUser SID into process memory.
/// The result must not be logged, used as a capability, or serialized.
#[cfg(windows)]
pub fn observe_current_process_user_sid() -> Result<Vec<u8>, SidObservationError> {
    windows::observe_current_process_user_sid()
}
/// Compares a SID supplied by a future *independently verified* Task Scheduler
/// reader with the current process's actual token. SID equality does not
/// authenticate the origin of a command or authorize any operation.
#[cfg(windows)]
pub fn compare_current_process_user_sid(
    expected: &[u8],
) -> Result<ProcessSidEvidence, SidObservationError> {
    if !windows::valid_sid_bytes(expected) {
        return Err(SidObservationError::Unverifiable);
    }
    let current = observe_current_process_user_sid()?;
    Ok(if current == expected {
        ProcessSidEvidence::SameAccount
    } else {
        ProcessSidEvidence::DifferentAccount
    })
}

#[cfg(windows)]
mod task_scheduler;

/// Identity class of the *security-descriptor owner* on a registered task.
/// The owner's SID is not the scheduled execution principal's SID. This
/// observation does not grant access, establish installer provenance or prove
/// the task's DACL safely restricts access.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskOwnerEvidence {
    CurrentUser,
    BuiltinAdministrators,
    DifferentOwner,
}

/// Reads task security descriptor owner from local Windows Task Scheduler COM.
/// Requires a syntactically valid descriptor with explicit, non-null DACL.
/// Never use as authorization; an admin-owned task is not necessarily ours.
#[cfg(windows)]
pub fn observe_registered_task_owner_for_observation(
    task_name: &str,
) -> Result<TaskOwnerEvidence, SidObservationError> {
    task_scheduler::observe_registered_task_owner(task_name)
}

/// Reads a real Task Scheduler registration through local COM and compares
/// its principal with the process TokenUser. Never an authorization grant.
/// This public observer accepts only single-component task names; an installed
/// instance must later establish the exact trusted task/provenance separately.
#[cfg(windows)]
pub fn compare_registered_task_principal_for_observation(
    task_name: &str,
) -> Result<ProcessSidEvidence, SidObservationError> {
    task_scheduler::compare_registered_task_principal(task_name)
}

/// Convenience observer for the repository's canonical Windows tunnel task.
/// Identity equality alone cannot authorize a remote or local caller.
#[cfg(windows)]
pub fn compare_registered_tunnel_task_principal() -> Result<ProcessSidEvidence, SidObservationError>
{
    compare_registered_task_principal_for_observation("Desktop Commander Windows Tunnel")
}

/// Structural observations of a *fixture-rooted* Windows file only.
/// This never authenticates a registered installation, local operator or
/// permission to read or replace the file's secret bytes.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCustodyEvidence {
    ObservedOnly,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCustodyDenied {
    Unverifiable,
}

#[cfg(windows)]
mod file_custody;

/// Experimental read-only metadata inspection. The root is supplied by the
/// caller and is **not** authenticated here. Never use this as an operations
/// authorization, nor expose arbitrary roots over the MCP or an admin CLI.
#[cfg(windows)]
pub fn observe_private_file_custody(
    fixture_root: &std::path::Path,
    relative_file: &std::path::Path,
) -> Result<FileCustodyEvidence, FileCustodyDenied> {
    file_custody::observe(fixture_root, relative_file)
}

#[cfg(windows)]
mod relative_sd;

#[cfg(windows)]
mod system_executable;

/// Read-only identity evidence from a native Windows file handle.
/// This is NOT a signed-publisher verification, a protected installation
/// record, an executable launch token or an authorization decision.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsSystemExecutableObservation {
    pub path: std::path::PathBuf,
    pub volume_serial: u32,
    pub file_index: u64,
    pub link_count: u32,
}

/// Observe the OS-reported System32 schtasks.exe with Win32 APIs and a file
/// handle, without consulting SystemRoot, PATH, task XML, CLI or environment.
/// The handle is closed before return. Do not use the returned path as a
/// permission to start a subprocess; reverify custody at the launch boundary.
#[cfg(windows)]
pub fn observe_os_schtasks_for_observation(
) -> Result<OsSystemExecutableObservation, SidObservationError> {
    system_executable::observe()
}
