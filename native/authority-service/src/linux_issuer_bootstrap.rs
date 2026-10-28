//! Read-only, OS-attested issuer bootstrap: NO operational grant exists.
//! Policy, native root handles and writable replay file are all observed
//! independently before returning. SQLite VFS attachment remains UNAVAILABLE.
use crate::{
    issuer_policy::IssuerPolicy, linux_replay_file::ObservedReplayFile,
    sealed_dispatch::SealedDirectoryGrant, IdentityDenied,
};

/// Retains the already-open native roots and the OS-pinned replay-file
/// observation. Nothing exposes those handles or approves MCP operations.
pub struct UnissuedIssuer {
    roots: Vec<SealedDirectoryGrant>,
    replay_file: ObservedReplayFile,
    policy_epoch: u64,
    policy_digest: [u8; 32],
    revoked: bool,
}

impl UnissuedIssuer {
    /// No input pathname, requested rootRef, epoch or caller-supplied digest.
    pub fn observe_os_attested() -> Result<Self, IdentityDenied> {
        let policy = IssuerPolicy::from_os_attested()?;
        let replay_file = ObservedReplayFile::from_os_attested()?;
        let mut roots = Vec::new();
        for root_ref in policy.root_refs() {
            roots.push(
                SealedDirectoryGrant::from_issuer_policy(&policy, root_ref)
                    .map_err(|_| IdentityDenied)?,
            );
        }
        // Repeat the administrator witness+policy observation after all
        // potentially blocking kernel-root acquisitions. A changed generation
        // never silently becomes a grant.
        let after = IssuerPolicy::from_os_attested()?;
        if policy.epoch() != after.epoch() || policy.digest() != after.digest() {
            return Err(IdentityDenied);
        }
        // A valid inode/header is insufficient: verify actual on-disk SQLite
        // schema and every bounded replay identity against the witnessed epoch.
        replay_file.read_verified_snapshot(policy.epoch())?;
        Ok(Self {
            roots,
            replay_file,
            policy_epoch: policy.epoch(),
            policy_digest: *policy.digest(),
            revoked: false,
        })
    }

    /// Sticky revalidation: an unchanged OS observation is not an ability
    /// to execute or issue a replay-authorized capability.
    pub fn revalidate(&mut self) -> Result<(), IdentityDenied> {
        if self.revoked {
            return Err(IdentityDenied);
        }
        let observation = IssuerPolicy::from_os_attested();
        if self
            .replay_file
            .read_verified_snapshot(self.policy_epoch)
            .is_err()
            || !matches!(observation, Ok(ref p)
                if p.epoch() == self.policy_epoch
                && p.digest() == &self.policy_digest)
        {
            self.revoke();
            return Err(IdentityDenied);
        }
        Ok(())
    }
    pub fn observed_root_count(&self) -> usize {
        self.roots.len()
    }
    pub fn epoch(&self) -> u64 {
        self.policy_epoch
    }
    pub fn replay_file_identity(&self) -> (u64, u64) {
        self.replay_file.identity()
    }
    /// No reactivation. All retained native grants remain deny-only because
    /// their replay admission has not been backed by an OS-authenticated VFS.
    pub fn revoke(&mut self) {
        self.revoked = true;
        for grant in &mut self.roots {
            grant.revoke();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_unprovisioned_process_cannot_bootstrap_privileged_issuer() {
        assert!(UnissuedIssuer::observe_os_attested().is_err());
    }
}
