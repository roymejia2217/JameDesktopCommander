//! Internal structural gate for OS-issued local IPC peer credentials.
//! This function does NOT authorize a client and must NEVER process claimed
//! identities from a request frame, command line or environment variable.
use crate::IdentityDenied;

// Structural rejection only. This must be called solely on a kernel-issued
// connected-peer observation, never a claimed UID/GID in client payloads.
pub(super) fn validate_kernel_peer(pid: i32, uid: u32, gid: u32) -> Result<(), IdentityDenied> {
    if pid <= 0 || uid == 0 || gid == 0 {
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_peer_snapshot_must_identify_a_nonroot_process_and_group() {
        assert_eq!(validate_kernel_peer(42, 1001, 1001), Ok(()));
        for (pid, uid, gid) in [
            (0, 1001, 1001),
            (-1, 1001, 1001),
            (42, 0, 1001),
            (42, 1001, 0),
            (0, 0, 0),
        ] {
            assert_eq!(validate_kernel_peer(pid, uid, gid), Err(IdentityDenied));
        }
    }
}
