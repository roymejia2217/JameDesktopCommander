//! Pure deny-by-default comparison of kernel-reported peer credentials with
//! an independently provisioned service account. No IPC or file authority.

use crate::IdentityDenied;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelPeer {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

// No protected client-account source is wired yet; this value cannot
// authorize runtime operations. Retained only for reviewed future admission.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DedicatedAccount {
    pub uid: u32,
    pub gid: u32,
}

/// The expected account MUST come from protected OS account resolution.
/// This comparison alone never makes a client authorized for filesystem I/O.
#[allow(dead_code)]
pub fn verify_distinct_peer(
    peer: KernelPeer,
    account: DedicatedAccount,
    service_uid: u32,
    service_gid: u32,
    service_pid: i32,
) -> Result<(), IdentityDenied> {
    if peer.pid <= 0
        || service_pid <= 0
        || peer.pid == service_pid
        || peer.uid == 0
        || peer.gid == 0
        || service_uid == 0
        || service_gid == 0
        || peer.uid == service_uid
        || peer.gid == service_gid
        || account.uid == 0
        || account.gid == 0
        || peer.uid != account.uid
        || peer.gid != account.gid
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

/// A message writer must be the exact kernel-observed connection owner.
/// This check is NOT a proof that the original process was issued by a
/// protected launcher. That independent admission gate remains mandatory.
pub fn verify_message_writer(
    connection: KernelPeer,
    writer: Option<KernelPeer>,
) -> Result<(), IdentityDenied> {
    let Some(writer) = writer else {
        return Err(IdentityDenied);
    };
    if connection.pid <= 0 || writer.pid <= 0 || writer != connection {
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transferred_connection_cannot_reuse_original_process_credentials() {
        let original = peer();
        assert_eq!(verify_message_writer(original, Some(original)), Ok(()));
        assert_eq!(verify_message_writer(original, None), Err(IdentityDenied));
        assert_eq!(
            verify_message_writer(
                KernelPeer {
                    pid: -1,
                    ..original
                },
                Some(original)
            ),
            Err(IdentityDenied),
        );
        assert_eq!(
            verify_message_writer(
                original,
                Some(KernelPeer {
                    pid: original.pid + 1,
                    ..original
                })
            ),
            Err(IdentityDenied),
            "a second process with the same UID/GID must never inherit original-origin authority",
        );
        assert_eq!(
            verify_message_writer(
                original,
                Some(KernelPeer {
                    uid: original.uid + 1,
                    ..original
                })
            ),
            Err(IdentityDenied),
        );
        assert_eq!(
            verify_message_writer(
                original,
                Some(KernelPeer {
                    gid: original.gid + 1,
                    ..original
                })
            ),
            Err(IdentityDenied),
        );
    }

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
            verify_distinct_peer(peer(), expected(), 23003, 23005, 41002),
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
                verify_distinct_peer(observation, expected(), 23003, 23005, 41002),
                Err(IdentityDenied)
            );
        }
    }

    #[test]
    fn must_not_accept_same_principal_or_pid_as_authority() {
        assert_eq!(
            verify_distinct_peer(peer(), expected(), peer().uid, 23005, 41002),
            Err(IdentityDenied)
        );
        assert_eq!(
            verify_distinct_peer(peer(), expected(), 23003, 23005, peer().pid),
            Err(IdentityDenied)
        );
    }

    #[test]
    fn distinct_uid_with_service_primary_group_must_still_deny() {
        // The client cannot inherit the authority's primary group even
        // when its UID differs: group DAC can still expose protected state.
        assert_eq!(
            verify_distinct_peer(peer(), expected(), 23003, 23002, 41002),
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
                verify_distinct_peer(peer(), account, 23003, 23005, 41002),
                Err(IdentityDenied)
            );
        }
        assert_eq!(
            verify_distinct_peer(peer(), expected(), 0, 23005, 41002),
            Err(IdentityDenied)
        );
        assert_eq!(
            verify_distinct_peer(peer(), expected(), 23003, 0, 41002),
            Err(IdentityDenied)
        );
        assert_eq!(
            verify_distinct_peer(peer(), expected(), 23003, 23005, -1),
            Err(IdentityDenied)
        );
    }
}
