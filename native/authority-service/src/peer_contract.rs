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

// These are Linux AF_UNIX/SOCK_STREAM numeric ABI constants. The structural
// gate is intentionally testable on Windows without pretending to open IPC.
pub(super) fn validate_connected_unix_stream(
    domain: i32,
    socket_type: i32,
    connected: bool,
) -> Result<(), IdentityDenied> {
    if domain != 1 || socket_type != 1 || !connected {
        return Err(IdentityDenied);
    }
    Ok(())
}

/// Compare the observed kernel credential snapshot with separately
/// provisioned expected OS user/group identifiers. The caller must resolve
/// the expectation from administrator-controlled account state, never from a
/// field transmitted by the connected peer. No filesystem grant results.
pub(super) fn validate_expected_kernel_peer(
    pid: i32,
    observed_uid: u32,
    observed_gid: u32,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), IdentityDenied> {
    validate_kernel_peer(pid, observed_uid, observed_gid)?;
    if expected_uid == 0
        || expected_gid == 0
        || observed_uid != expected_uid
        || observed_gid != expected_gid
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_connected_unix_streams_may_supply_peer_evidence() {
        assert_eq!(validate_connected_unix_stream(1, 1, true), Ok(()));
        for (domain, socket_type, connected) in [
            (2, 1, true),  // AF_INET stream is not a local Unix transport
            (1, 2, true),  // AF_UNIX datagram is not a connected stream
            (1, 1, false), // unconnected socket/listener has no accepted peer
            (0, 1, true),
            (1, 0, true),
        ] {
            assert_eq!(
                validate_connected_unix_stream(domain, socket_type, connected),
                Err(IdentityDenied)
            );
        }
    }

    #[test]
    fn only_exact_nonroot_expected_system_identity_may_match_a_kernel_peer() {
        assert_eq!(
            validate_expected_kernel_peer(502, 1101, 1201, 1101, 1201),
            Ok(())
        );
        for (pid, observed_uid, observed_gid, approved_uid, approved_gid) in [
            (0, 1101, 1201, 1101, 1201),
            (502, 1102, 1201, 1101, 1201),
            (502, 1101, 1202, 1101, 1201),
            (502, 0, 1201, 0, 1201),
            (502, 1101, 0, 1101, 0),
            (502, 1101, 1201, 0, 1201),
            (502, 1101, 1201, 1101, 0),
        ] {
            assert_eq!(
                validate_expected_kernel_peer(
                    pid,
                    observed_uid,
                    observed_gid,
                    approved_uid,
                    approved_gid,
                ),
                Err(IdentityDenied),
                "unapproved kernel credential pair must deny",
            );
        }
    }

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
