//! OS-attested, NON-ISSUING bootstrap: NO operational grant exists.
//! Policy, native handles, pinned SQLite reader and standard SQLite unix-VFS
//! writer are bound independently. Durable claims cannot authorize execution
//! until authenticated IPC, independent antirollback and grant issuance pass.
use crate::{
    issuer_policy::IssuerPolicy, linux_replay_file::ObservedReplayFile,
    sealed_dispatch::SealedDirectoryGrant, unix_peer::PreparedMcpClient, IdentityDenied,
};
use jdc_authority_store::linux_replay_writer::LinuxReplayIssuerLedger;
use std::os::fd::AsFd;

/// Central socket liveness check shared by generic issuer revalidation.
/// Production supplies only its retained systemd FD, fixed endpoint and
/// kernel/NSS identities. The parent UID argument exists for real Linux
/// unprivileged test sockets; production always passes the root owner (0).
fn revalidate_listener_custody(
    listener: &std::os::unix::net::UnixListener,
    expected_path: &std::path::Path,
    expected_service_uid: libc::uid_t,
    expected_client_gid: libc::gid_t,
    protected_parent_uid: libc::uid_t,
    revoked: &mut bool,
) -> Result<(), IdentityDenied> {
    crate::unix_activation::inspect_latched_custodied_named_listener(
        listener.as_fd(),
        expected_path,
        expected_service_uid,
        expected_client_gid,
        protected_parent_uid,
        revoked,
    )
}

/// Retains the already-open native roots and the OS-pinned replay-file
/// observation. Nothing exposes those handles or approves MCP operations.
/// A consumer must NOT admit an arbitrary caller-supplied UnixStream bypassing
/// the one retained systemd listener and its pre/post IPC custody checks.
///
/// ```compile_fail
/// use jdc_authority_service::linux_issuer_bootstrap::UnissuedIssuer;
/// let _unauthorized_stream_admission = UnissuedIssuer::inspect_client_frame;
/// ```
pub struct UnissuedIssuer {
    roots: Vec<SealedDirectoryGrant>,
    replay_file: ObservedReplayFile,
    replay_writer: LinuxReplayIssuerLedger,
    expected_client: PreparedMcpClient,
    inherited_listener: std::os::unix::net::UnixListener,
    policy_epoch: u64,
    policy_digest: [u8; 32],
    revoked: bool,
}

impl UnissuedIssuer {
    /// No input pathname, requested rootRef, epoch or caller-supplied digest.
    pub fn observe_os_attested() -> Result<Self, IdentityDenied> {
        let policy = IssuerPolicy::from_os_attested()?;
        let expected_client = PreparedMcpClient::from_provisioned_system_account()?;
        // A request listener supplied by a caller must not become privileged
        // IPC authority. Adopt the kernel's exact single inherited FD3 once.
        const ENDPOINT: &str = "/run/jdc-authority-ipc/authority.sock";
        let inherited_listener = crate::unix_activation::retain_inherited_systemd_listener(
            std::path::Path::new(ENDPOINT),
            unsafe { libc::geteuid() },
            expected_client.expected_gid(),
        )?;
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
        let mut replay_writer = LinuxReplayIssuerLedger::from_provisioned_service(policy.epoch())
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
            inherited_listener,
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
        // A generic liveness decision must not omit the retained kernel
        // listener's root-managed namespace merely because no IPC client is
        // currently being accepted. Repaired custody cannot revive this issuer.
        const ENDPOINT: &str = "/run/jdc-authority-ipc/authority.sock";
        if revalidate_listener_custody(
            &self.inherited_listener,
            std::path::Path::new(ENDPOINT),
            unsafe { libc::geteuid() },
            self.expected_client.expected_gid(),
            0,
            &mut self.revoked,
        )
        .is_err()
        {
            self.revoke();
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
    /// One genuine named AF_UNIX listener, with a fixed NSS client identity
    /// and a second protected-policy observation after bounded frame receipt.
    /// This does not establish systemd's provenance for the listener, nor
    /// grant any filesystem operation or acknowledge a client request.
    fn inspect_one_named_client(
        &mut self,
        listener: &std::os::unix::net::UnixListener,
        deadline: std::time::Duration,
    ) -> Result<(), IdentityDenied> {
        const ENDPOINT: &str = "/run/jdc-authority-ipc/authority.sock";
        let principal = self.expected_client;
        let named = std::path::Path::new(ENDPOINT);
        crate::unix_accept::observe_one_named_prepared_with_checks(
            listener,
            principal,
            named,
            deadline,
            // The generic issuer check now verifies the SAME retained kernel
            // listener custody before and after bounded IPC frame receipt,
            // together with replay state and protected administrator policy.
            || self.revalidate(),
        )
    }

    /// Only the FD retained from the one root-custodied activation
    /// inventory can be used by the future broker request loop.
    /// The duplicated handle shares the same kernel listening socket and
    /// remains non-authorizing; policy is still verified before/after read.
    pub fn inspect_one_inherited_client(
        &mut self,
        deadline: std::time::Duration,
    ) -> Result<(), IdentityDenied> {
        let listener = self
            .inherited_listener
            .try_clone()
            .map_err(|_| IdentityDenied)?;
        self.inspect_one_named_client(&listener, deadline)
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

    #[test]
    fn generic_issuer_liveness_check_must_revoke_after_socket_custody_drift() {
        use std::os::unix::fs::PermissionsExt;
        let home = std::env::var_os("HOME").expect("native Linux fixture needs HOME");
        let temp = tempfile::tempdir_in(home).unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = temp.path().join("authority.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert_ne!(uid, 0, "fixture must not run with privileged account");
        let mut revoked = false;
        assert_eq!(
            revalidate_listener_custody(&listener, &path, uid, gid, uid, &mut revoked),
            Ok(()),
            "valid kernel listener remains admissible"
        );
        assert!(!revoked);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            revalidate_listener_custody(&listener, &path, uid, gid, uid, &mut revoked),
            Err(IdentityDenied),
            "a liveness check must observe socket-custody loss without any IPC client"
        );
        assert!(revoked, "loss of custody must be sticky");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert_eq!(
            revalidate_listener_custody(&listener, &path, uid, gid, uid, &mut revoked),
            Err(IdentityDenied),
            "repair cannot reuse revoked issuer session"
        );
        let mut fresh = false;
        assert_eq!(
            revalidate_listener_custody(&listener, &path, uid, gid, uid, &mut fresh),
            Ok(()),
            "a new independently verified session may pass"
        );
    }
}
