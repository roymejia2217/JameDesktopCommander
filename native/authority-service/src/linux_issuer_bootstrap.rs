//! OS-attested, NON-ISSUING bootstrap: NO operational grant exists.
//! Policy, native handles, pinned SQLite reader and standard SQLite unix-VFS
//! writer are bound independently. Durable claims cannot authorize execution
//! until authenticated IPC, independent antirollback and grant issuance pass.
use crate::{
    issuer_policy::IssuerPolicy, linux_replay_file::ObservedReplayFile,
    sealed_dispatch::SealedDirectoryGrant, unix_peer::PreparedMcpClient, IdentityDenied,
};
use jdc_authority_store::linux_replay_writer::LinuxReplayIssuerLedger;

/// Retains the already-open native roots and the OS-pinned replay-file
/// observation. Nothing exposes those handles or approves MCP operations.
pub struct UnissuedIssuer {
    roots: Vec<SealedDirectoryGrant>,
    replay_file: ObservedReplayFile,
    replay_writer: LinuxReplayIssuerLedger,
    expected_client: PreparedMcpClient,
    policy_epoch: u64,
    policy_digest: [u8; 32],
    revoked: bool,
}

impl UnissuedIssuer {
    /// No input pathname, requested rootRef, epoch or caller-supplied digest.
    pub fn observe_os_attested() -> Result<Self, IdentityDenied> {
        let policy = IssuerPolicy::from_os_attested()?;
        let expected_client = PreparedMcpClient::from_provisioned_system_account()?;
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
        // Standard SQLite unix VFS only opens after OS principal, root and
        // full replay-image validation. No arbitrary path or client epoch.
        let replay_writer = LinuxReplayIssuerLedger::from_provisioned_service(policy.epoch())
            .map_err(|_| IdentityDenied)?;
        // Policy may change while SQLite acquires locks or checks schema.
        let completed = IssuerPolicy::from_os_attested()?;
        if completed.epoch() != policy.epoch() || completed.digest() != policy.digest() {
            return Err(IdentityDenied);
        }
        replay_writer
            .validate_custody()
            .map_err(|_| IdentityDenied)?;
        replay_file.read_verified_snapshot(policy.epoch())?;
        Ok(Self {
            roots,
            replay_file,
            replay_writer,
            expected_client,
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
            || self.replay_writer.validate_custody().is_err()
            || !matches!(observation, Ok(ref p)
                if p.epoch() == self.policy_epoch
                && p.digest() == &self.policy_digest)
        {
            self.revoke();
            return Err(IdentityDenied);
        }
        Ok(())
    }
    /// Authenticated client-frame observation, never an execution grant.
    /// The expected identity came only from fixed NSS at service bootstrap.
    pub fn inspect_client_frame(
        &mut self,
        stream: &std::os::unix::net::UnixStream,
        deadline: std::time::Duration,
    ) -> Result<(), IdentityDenied> {
        self.revalidate()?;
        crate::unix_session::read_prepared_client_frame(stream, &self.expected_client, deadline)
            .map(|_| ())
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
    /// No reactivation. Even a real SQLite writer cannot turn these
    /// native roots into operational grants without independent antirollback
    /// and authenticated IPC authority.
    pub fn revoke(&mut self) {
        self.revoked = true;
        self.replay_writer.revoke();
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
