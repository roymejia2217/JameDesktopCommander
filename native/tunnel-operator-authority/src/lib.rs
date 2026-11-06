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
