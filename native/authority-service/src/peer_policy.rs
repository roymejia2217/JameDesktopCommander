//! Pure deny-by-default comparison of kernel-reported peer credentials with
//! an independently provisioned service account. No IPC or file authority.

use crate::IdentityDenied;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelPeer {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

// No protected client-account source is wired yet; this value cannot
// authorize runtime operations. Retained only for reviewed future admission.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DedicatedAccount {
    pub uid: u32,
    pub gid: u32,
}

/// The expected account MUST come from protected OS account resolution.
/// This comparison alone never makes a client authorized for filesystem I/O.
#[allow(dead_code)]
pub(crate) fn verify_distinct_peer(
    peer: KernelPeer,
    account: DedicatedAccount,
    service_uid: u32,
    service_pid: i32,
) -> Result<(), IdentityDenied> {
    if peer.pid <= 0
        || service_pid <= 0
        || peer.pid == service_pid
        || peer.uid == 0
        || peer.gid == 0
        || service_uid == 0
        || peer.uid == service_uid
        || account.uid == 0
        || account.gid == 0
        || peer.uid != account.uid
        || peer.gid != account.gid
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> DedicatedAccount {
        DedicatedAccount {
            uid: 23001,
            gid: 23002,
        }
    }

    fn peer() -> KernelPeer {
        KernelPeer {
            pid: 41001,
            uid: 23001,
            gid: 23002,
        }
    }

    #[test]
    fn provisioned_distinct_client_can_pass_only_when_all_credentials_match() {
        assert_eq!(
            verify_distinct_peer(peer(), expected(), 23003, 41002),
            Ok(())
        );
    }

    #[test]
    fn wrong_peer_identity_and_group_always_deny() {
        for observation in [
            KernelPeer {
                uid: 23004,
                ..peer()
            },
            KernelPeer {
                gid: 23004,
                ..peer()
            },
            KernelPeer { uid: 0, ..peer() },
            KernelPeer { gid: 0, ..peer() },
            KernelPeer { pid: 0, ..peer() },
            KernelPeer { pid: -1, ..peer() },
        ] {
            assert_eq!(
                verify_distinct_peer(observation, expected(), 23003, 41002),
                Err(IdentityDenied)
            );
        }
    }

    #[test]
    fn must_not_accept_same_principal_or_pid_as_authority() {
        assert_eq!(
            verify_distinct_peer(peer(), expected(), peer().uid, 41002),
            Err(IdentityDenied)
        );
        assert_eq!(
            verify_distinct_peer(peer(), expected(), 23003, peer().pid),
            Err(IdentityDenied)
        );
    }

    #[test]
    fn zero_or_malformed_provisioning_is_not_an_identity_grant() {
        for account in [
            DedicatedAccount { uid: 0, gid: 23002 },
            DedicatedAccount { uid: 23001, gid: 0 },
            DedicatedAccount {
                uid: 23004,
                gid: 23002,
            },
            DedicatedAccount {
                uid: 23001,
                gid: 23004,
            },
        ] {
            assert_eq!(
                verify_distinct_peer(peer(), account, 23003, 41002),
                Err(IdentityDenied)
            );
        }
        assert_eq!(
            verify_distinct_peer(peer(), expected(), 0, 41002),
            Err(IdentityDenied)
        );
        assert_eq!(
            verify_distinct_peer(peer(), expected(), 23003, -1),
            Err(IdentityDenied)
        );
    }
}
