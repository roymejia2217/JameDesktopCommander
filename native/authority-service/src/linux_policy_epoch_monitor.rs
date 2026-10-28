//! Process-local, sticky epoch/digest change detection for a Linux policy
//! generation observed via OS-validated administrator-owned handles.
//! NON-RELEASE: this is NOT a grant, issuer, reader lock, durable counter,
//! or authorization to execute MCP tools.
use crate::{linux_epoch_anchor::observe_matching_admin_policy_snapshot, IdentityDenied};

/// Never accepts caller-provided policy roots, paths, identities, or epochs.
/// A newly constructed monitor is NOT proof that a previous monitor stayed
/// active; a future issuer must own one process-lifetime state machine.
pub struct PolicyEpochMonitor {
    epoch: u64,
    digest: [u8; 32],
    permanently_revoked: bool,
}

impl PolicyEpochMonitor {
    /// Obtain the initial generation from two independently checked root
    /// witness reads enclosing OS-pinned, immutable SQLite policy bytes.
    /// A missing/unmatched witness, invalid account or DB must DENY.
    pub fn from_current_os_attested() -> Result<Self, IdentityDenied> {
        let snapshot = observe_matching_admin_policy_snapshot()?;
        Self::from_verified_parts(snapshot.epoch(), *snapshot.digest())
    }

    fn from_verified_parts(epoch: u64, digest: [u8; 32]) -> Result<Self, IdentityDenied> {
        if epoch == 0 || digest == [0; 32] {
            return Err(IdentityDenied);
        }
        Ok(Self {
            epoch,
            digest,
            permanently_revoked: false,
        })
    }

    /// Re-observe real OS-protected policy+witness; do not advance this
    /// monitor implicitly if the administrator publishes a new epoch.
    /// Any unreadable source or discrepancy irreversibly revokes it.
    /// There is no mechanism here for issuing or refreshing a grant.
    pub fn revalidate_current(&mut self) -> Result<(), IdentityDenied> {
        if self.permanently_revoked {
            return Err(IdentityDenied);
        }
        let observed = observe_matching_admin_policy_snapshot()
            .map(|snapshot| (snapshot.epoch(), *snapshot.digest()));
        self.observe_or_poison(observed)
    }

    fn observe_or_poison(
        &mut self,
        observed: Result<(u64, [u8; 32]), IdentityDenied>,
    ) -> Result<(), IdentityDenied> {
        if self.permanently_revoked {
            return Err(IdentityDenied);
        }
        match observed {
            Ok((epoch, digest))
                if epoch == self.epoch
                    && digest == self.digest
                    && epoch != 0
                    && digest != [0; 32] =>
            {
                Ok(())
            }
            _ => {
                self.permanently_revoked = true;
                Err(IdentityDenied)
            }
        }
    }

    /// Bind one issued capability to exactly the observed, administrator
    /// protected epoch AND policy digest. A changed generation poisons the
    /// process-local monitor even when a supplied client epoch looks valid.
    pub(crate) fn revalidate_issued_policy(
        &mut self,
        epoch: u64,
        digest: &[u8; 32],
    ) -> Result<(), IdentityDenied> {
        self.revalidate_current()?;
        self.assert_issued_identity(epoch, digest)
    }

    fn assert_issued_identity(
        &mut self,
        epoch: u64,
        digest: &[u8; 32],
    ) -> Result<(), IdentityDenied> {
        if self.permanently_revoked || self.epoch != epoch || &self.digest != digest {
            self.permanently_revoked = true;
            return Err(IdentityDenied);
        }
        Ok(())
    }

    /// An observation of revocation is permanent for this instance, even if
    /// a prior valid policy image and witness are restored later.
    pub fn is_revoked(&self) -> bool {
        self.permanently_revoked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: [u8; 32] = [0x11; 32];
    const NEW: [u8; 32] = [0x22; 32];

    #[test]
    fn issued_capability_must_match_exact_observed_epoch_and_digest() {
        for (epoch, digest) in [(8, OLD), (7, NEW), (0, OLD)] {
            let mut monitor = PolicyEpochMonitor::from_verified_parts(7, OLD).unwrap();
            assert_eq!(monitor.observe_or_poison(Ok((7, OLD))), Ok(()));
            assert_eq!(
                monitor.assert_issued_identity(epoch, &digest),
                Err(IdentityDenied)
            );
            assert!(monitor.is_revoked());
            assert_eq!(monitor.assert_issued_identity(7, &OLD), Err(IdentityDenied));
        }
        let mut monitor = PolicyEpochMonitor::from_verified_parts(7, OLD).unwrap();
        assert_eq!(monitor.observe_or_poison(Ok((7, OLD))), Ok(()));
        assert_eq!(monitor.assert_issued_identity(7, &OLD), Ok(()));
        assert!(!monitor.is_revoked());
    }

    #[test]
    fn rejects_unauthenticated_or_uninitialized_initial_generation() {
        assert!(PolicyEpochMonitor::from_verified_parts(0, OLD).is_err());
        assert!(PolicyEpochMonitor::from_verified_parts(7, [0; 32]).is_err());
    }

    #[test]
    fn unchanged_observation_accepts_without_implicit_advance() {
        let mut monitor = PolicyEpochMonitor::from_verified_parts(7, OLD).unwrap();
        for _ in 0..3 {
            assert_eq!(monitor.observe_or_poison(Ok((7, OLD))), Ok(()));
        }
        assert!(!monitor.is_revoked());
    }

    #[test]
    fn changed_epoch_or_digest_revokes_the_observed_generation() {
        for changed in [
            (8, NEW),     // forward publication
            (6, OLD),     // rollback
            (7, NEW),     // same-epoch content substitution
            (8, OLD),     // epoch advance with stale digest
            (7, [0; 32]), // malformed witness
            (0, OLD),
        ] {
            let mut monitor = PolicyEpochMonitor::from_verified_parts(7, OLD).unwrap();
            assert_eq!(monitor.observe_or_poison(Ok(changed)), Err(IdentityDenied));
            assert!(monitor.is_revoked());
        }
    }

    #[test]
    fn sticky_denial_prevents_reactivation_after_rollback() {
        let mut monitor = PolicyEpochMonitor::from_verified_parts(7, OLD).unwrap();
        assert_eq!(monitor.observe_or_poison(Ok((8, NEW))), Err(IdentityDenied));
        // Restoring BOTH old SQLite and witness cannot reactivate this
        // already poisoned process generation. Restart rollback is separate.
        assert_eq!(monitor.observe_or_poison(Ok((7, OLD))), Err(IdentityDenied));
        assert!(monitor.is_revoked());
    }

    #[test]
    fn source_read_failure_is_sticky_even_if_sources_later_recover() {
        let mut monitor = PolicyEpochMonitor::from_verified_parts(7, OLD).unwrap();
        assert_eq!(
            monitor.observe_or_poison(Err(IdentityDenied)),
            Err(IdentityDenied)
        );
        assert_eq!(monitor.observe_or_poison(Ok((7, OLD))), Err(IdentityDenied));
        assert!(monitor.is_revoked());
    }

    #[test]
    fn ordinary_unprovisioned_user_cannot_construct_authenticated_monitor() {
        assert!(PolicyEpochMonitor::from_current_os_attested().is_err());
    }
}
