//! OS-attested, non-transferable issuer bootstrap.
//! Policy, native handles, pinned SQLite reader and standard SQLite unix-VFS
//! writer are bound independently. One non-release read path now executes
//! entirely inside this issuer after authenticated IPC and a durable claim;
//! no handle or reusable grant escapes. The installed binary remains deny-only,
//! and independent restart antirollback plus namespace/object races remain P0.
use crate::{
    issuer_policy::IssuerPolicy,
    linux_replay_file::ObservedReplayFile,
    sealed_dispatch::{DispatchDenied, SealedDirectoryGrant},
    unix_peer::PreparedMcpClient,
    unix_session::AuthenticatedFrame,
    IdentityDenied,
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

/// Require the two independently OS-opened replay SQLite handles to refer to
/// exactly the same kernel object. File names, headers, size and separate
/// custody checks are insufficient when a name changes between opens.
/// This is NOT a complete SQLite transaction/replay or restart antirollback.
fn require_consistent_replay_pair(
    observer: (u64, u64),
    writer: (u64, u64),
) -> Result<(), IdentityDenied> {
    if observer.1 == 0 || observer != writer {
        return Err(IdentityDenied);
    }
    Ok(())
}

fn execute_claimed_read_on_roots(
    roots: &mut [SealedDirectoryGrant],
    policy_epoch: u64,
    frame: AuthenticatedFrame,
    claim: impl FnOnce([u8; 16]) -> Result<(), DispatchDenied>,
) -> Result<Vec<u8>, DispatchDenied> {
    let request = crate::canonical_request::decode_read_file_frame(frame.wire())
        .map_err(|_| DispatchDenied)?;
    if request.expected_epoch() != policy_epoch {
        return Err(DispatchDenied);
    }
    let selected = roots
        .iter_mut()
        .find(|root| root.matches_bound_identity(request.root_ref(), request.expected_epoch()))
        .ok_or(DispatchDenied)?;
    selected.execute_authenticated_read_with_external_claim(frame, claim)
}

/// Bind an authenticated listing frame to an issuer-retained root, its
/// witnessed policy epoch and one durable replay claim. The result is
/// serialized only after bounded handle-relative enumeration succeeds.
/// This is an internal research operation, never a Node-side path grant.
fn execute_claimed_list_on_roots(
    roots: &mut [SealedDirectoryGrant],
    policy_epoch: u64,
    frame: AuthenticatedFrame,
    claim: impl FnOnce([u8; 16]) -> Result<(), DispatchDenied>,
) -> Result<Vec<u8>, DispatchDenied> {
    let request = crate::canonical_request::decode_list_directory_frame(frame.wire())
        .map_err(|_| DispatchDenied)?;
    if request.expected_epoch() != policy_epoch {
        return Err(DispatchDenied);
    }
    let selected = roots
        .iter_mut()
        .find(|root| root.matches_bound_identity(request.root_ref(), request.expected_epoch()))
        .ok_or(DispatchDenied)?;
    let entries = selected.execute_authenticated_list_with_external_claim(frame, claim)?;
    serde_json::to_vec(&entries).map_err(|_| DispatchDenied)
}

/// Retains the already-open native roots and the OS-pinned replay-file
/// observation. Handles and replay authority never escape this object. Its
/// non-release read dispatcher accepts only the retained systemd listener and
/// bootstrap-prepared principal; a consumer must NOT admit an arbitrary
/// caller-supplied UnixStream or caller-selected root.
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
        // Even two independently valid root-custodied SQLite opens cannot
        // form a single replay authority if they refer to different inodes.
        // Bind the pinned snapshot reader and SQLite writer at bootstrap.
        require_consistent_replay_pair(replay_file.identity(), replay_writer.file_identity())?;
        // A root can be renamed/replaced while the writer acquires locks.
        // Never finish bootstrap with an FD that no longer represents the
        // administrator policy's current named directory.
        for root in &mut roots {
            root.revalidate_root_binding(&completed)
                .map_err(|_| IdentityDenied)?;
        }
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
        // Compare each retained root FD to a fresh, policy-selected OS root
        // handle. A renamed/replaced directory is no longer an issued root.
        // Observation alone cannot guarantee immunity to concurrent rename;
        // durable authorization and operation linearization remain P0.
        let roots_match = matches!(observation, Ok(ref p)
            if p.epoch() == self.policy_epoch
            && p.digest() == &self.policy_digest
            && self.roots.iter_mut().all(|root| root.revalidate_root_binding(p).is_ok()));
        if require_consistent_replay_pair(
            self.replay_file.identity(),
            self.replay_writer.file_identity(),
        )
        .is_err()
            || self
                .replay_file
                .read_verified_snapshot(self.policy_epoch)
                .is_err()
            || self.replay_writer.validate_custody().is_err()
            || !roots_match
        {
            self.revoke();
            return Err(IdentityDenied);
        }
        Ok(())
    }

    fn execute_claimed_read(
        &mut self,
        frame: AuthenticatedFrame,
    ) -> Result<Vec<u8>, DispatchDenied> {
        if self.revoked {
            return Err(DispatchDenied);
        }
        let epoch = self.policy_epoch;
        let (roots, replay_writer) = (&mut self.roots, &mut self.replay_writer);
        execute_claimed_read_on_roots(roots, epoch, frame, |request_id| {
            replay_writer
                .claim_once(request_id)
                .map_err(|_| DispatchDenied)
        })
    }

    fn execute_claimed_list(
        &mut self,
        frame: AuthenticatedFrame,
    ) -> Result<Vec<u8>, DispatchDenied> {
        if self.revoked {
            return Err(DispatchDenied);
        }
        let epoch = self.policy_epoch;
        let (roots, replay_writer) = (&mut self.roots, &mut self.replay_writer);
        execute_claimed_list_on_roots(roots, epoch, frame, |request_id| {
            replay_writer
                .claim_once(request_id)
                .map_err(|_| DispatchDenied)
        })
    }

    /// Non-release integration boundary. It only uses the listener retained
    /// from systemd activation and the fixed bootstrap-prepared MCP principal;
    /// no caller can inject a root handle, replay store, UID/GID or pathname.
    /// The installed binary remains deny-only and does not call this method.
    pub fn dispatch_one_inherited_read_reply(
        &mut self,
        deadline: std::time::Duration,
    ) -> Result<(), DispatchDenied> {
        let listener = self
            .inherited_listener
            .try_clone()
            .map_err(|_| DispatchDenied)?;
        let principal = self.expected_client;
        crate::unix_accept::dispatch_one_named_prepared_read_reply(
            &listener,
            self,
            principal,
            deadline,
            |issuer| issuer.revalidate().map_err(|_| DispatchDenied),
            |issuer, frame| issuer.execute_claimed_read(frame),
            |issuer| issuer.revoke(),
        )
    }

    /// Experimental authenticated listing response using the exact retained
    /// systemd listener, protected issuer epoch and OS-pinned root handles.
    /// The response is bounded JSON bytes of accepted entry names; the
    /// production binary still never calls this non-release method.
    pub fn dispatch_one_inherited_list_reply(
        &mut self,
        deadline: std::time::Duration,
    ) -> Result<(), DispatchDenied> {
        let listener = self
            .inherited_listener
            .try_clone()
            .map_err(|_| DispatchDenied)?;
        let principal = self.expected_client;
        crate::unix_accept::dispatch_one_named_prepared_read_reply(
            &listener,
            self,
            principal,
            deadline,
            |issuer| issuer.revalidate().map_err(|_| DispatchDenied),
            |issuer, frame| issuer.execute_claimed_list(frame),
            |issuer| issuer.revoke(),
        )
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
    fn two_valid_replay_sqlite_handles_must_be_same_kernel_object() {
        use std::os::unix::fs::MetadataExt;
        let home = std::env::var_os("HOME").expect("native Linux runner provides HOME");
        let temp = tempfile::tempdir_in(home).unwrap();
        let original = temp.path().join("claims.sqlite3");
        let parked = temp.path().join("parked.sqlite3");
        let replacement = temp.path().join("replacement.sqlite3");
        for file in [&original, &replacement] {
            let db = rusqlite::Connection::open(file).unwrap();
            db.execute_batch(concat!(
                "PRAGMA application_id=0x4A44434C; PRAGMA user_version=1;",
                "CREATE TABLE replay_claims (epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), ",
                "request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)=16), ",
                "PRIMARY KEY(epoch,request)) WITHOUT ROWID"
            ))
            .unwrap();
        }
        // Both files must pass the actual read-only replay-image validator;
        // otherwise the denial could be caused by invalid SQLite content.
        for file in [&original, &replacement] {
            assert_eq!(
                jdc_authority_store::replay_ledger::ReplayClaimLedger::inspect_serialized_snapshot(
                    &std::fs::read(file).unwrap(),
                    7
                ),
                Ok(0),
                "attacker replacement is a valid empty replay SQLite image"
            );
        }
        let observed = std::fs::File::open(&original).unwrap();
        let first = observed.metadata().unwrap();
        let same_name = std::fs::File::open(&original).unwrap().metadata().unwrap();
        let held_id = (first.dev(), first.ino());
        assert_eq!(
            require_consistent_replay_pair(held_id, (same_name.dev(), same_name.ino())),
            Ok(()),
            "two independent opens of the unchanged SQLite inode must be admissible"
        );
        std::fs::rename(&original, &parked).unwrap();
        std::fs::rename(&replacement, &original).unwrap();
        let writer = std::fs::File::open(&original).unwrap();
        let second = writer.metadata().unwrap();
        let current_id = (second.dev(), second.ino());
        assert_ne!(held_id, current_id, "real rename positive control");
        assert_eq!(
            require_consistent_replay_pair(held_id, current_id),
            Err(IdentityDenied),
            "individually valid SQLite handles cannot be bound across different inodes"
        );
        std::fs::rename(&original, &replacement).unwrap();
        std::fs::rename(&parked, &original).unwrap();
        assert_eq!(
            require_consistent_replay_pair(held_id, current_id),
            Err(IdentityDenied),
            "restoring a filename does not change the identity of an already opened writer"
        );
        let repaired = std::fs::File::open(&original).unwrap().metadata().unwrap();
        assert_eq!(
            require_consistent_replay_pair(held_id, (repaired.dev(), repaired.ino())),
            Ok(()),
            "a newly opened same-object pair can pass identity binding"
        );
    }

    #[test]
    fn linux_issuer_root_selection_claims_once_for_bounded_listing() {
        use std::io::Write;
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        const ROOT: &str = "0123456789abcdef0123456789abcdef";
        const ID: &str = "11111111-1111-4111-8111-111111111111";
        let home = std::env::var_os("HOME").unwrap();
        let temp = tempfile::tempdir_in(home).unwrap();
        let allowed = temp.path().join("allowed");
        let nested = allowed.join("nested");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(nested.join("z.txt"), b"Z").unwrap();
        std::fs::write(nested.join("a.txt"), b"A").unwrap();
        let sentinel = outside.join("sentinel.bin");
        std::fs::write(&sentinel, b"OUTSIDE_UNCHANGED").unwrap();
        let policy_bytes = format!(
            r#"{{"version":1,"mode":"restricted","roots":[{{"rootRef":"{ROOT}","absolutePath":{}}}]}}"#,
            serde_json::to_string(allowed.to_str().unwrap()).unwrap(),
        );
        let policy =
            IssuerPolicy::decode_exact_for_test(policy_bytes.as_bytes(), 7, [1; 32]).unwrap();
        let mut roots = vec![SealedDirectoryGrant::from_issuer_policy(&policy, ROOT).unwrap()];
        let frame = |root: &str, epoch: u64| {
            let body = format!(
                r#"{{"version":1,"kind":"list-directory","requestId":"{ID}","expectedEpoch":"{epoch}","rootRef":"{root}","relativePath":"nested"}}"#,
            );
            let mut wire = (body.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(body.as_bytes());
            let (mut sender, receiver) = UnixStream::pair().unwrap();
            sender.write_all(&wire).unwrap();
            sender.shutdown(Shutdown::Write).unwrap();
            crate::unix_session::read_authenticated_frame(
                &receiver,
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                Duration::from_secs(1),
            )
            .unwrap()
        };
        let mut claims = 0;
        let accepted = execute_claimed_list_on_roots(&mut roots, 7, frame(ROOT, 7), |_| {
            claims += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(accepted, br#"["a.txt","z.txt"]"#);
        for (root, epoch) in [(ROOT, 8), ("00000000000000000000000000000000", 7)] {
            assert_eq!(
                execute_claimed_list_on_roots(&mut roots, 7, frame(root, epoch), |_| {
                    claims += 1;
                    Ok(())
                }),
                Err(DispatchDenied),
            );
        }
        assert_eq!(claims, 1);
        assert_eq!(std::fs::read(sentinel).unwrap(), b"OUTSIDE_UNCHANGED");
    }

    #[test]
    fn issuer_root_selection_claims_once_before_handle_bounded_read() {
        use std::io::Write;
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        const ROOT: &str = "0123456789abcdef0123456789abcdef";
        let home = std::env::var_os("HOME").expect("native Linux fixture needs HOME");
        let temp = tempfile::tempdir_in(home).unwrap();
        let allowed = temp.path().join("allowed");
        std::fs::create_dir(&allowed).unwrap();
        let expected = b"ISSUER_SELECTED_ROOT";
        std::fs::write(allowed.join("inside.bin"), expected).unwrap();
        let policy_bytes = format!(
            r#"{{"version":1,"mode":"restricted","roots":[{{"rootRef":"{ROOT}","absolutePath":{}}}]}}"#,
            serde_json::to_string(allowed.to_str().unwrap()).unwrap(),
        );
        let policy =
            IssuerPolicy::decode_exact_for_test(policy_bytes.as_bytes(), 7, [1; 32]).unwrap();
        let mut roots = vec![SealedDirectoryGrant::from_issuer_policy(&policy, ROOT).unwrap()];

        let authenticated = |root: &str, epoch: u64, request_id: &str| {
            let body = format!(
                r#"{{"version":1,"kind":"read-file","requestId":"{request_id}","expectedEpoch":"{epoch}","rootRef":"{root}","relativePath":"inside.bin"}}"#,
            );
            let mut wire = (body.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(body.as_bytes());
            let (mut sender, receiver) = UnixStream::pair().unwrap();
            sender.write_all(&wire).unwrap();
            sender.shutdown(Shutdown::Write).unwrap();
            crate::unix_session::read_authenticated_frame(
                &receiver,
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                Duration::from_secs(1),
            )
            .unwrap()
        };

        let mut claims = Vec::new();
        let result = execute_claimed_read_on_roots(
            &mut roots,
            7,
            authenticated(ROOT, 7, "44444444-4444-4444-8444-444444444444"),
            |id| {
                claims.push(id);
                Result::<(), crate::sealed_dispatch::DispatchDenied>::Ok(())
            },
        );
        assert_eq!(result, Ok(expected.to_vec()));
        assert_eq!(
            claims.len(),
            1,
            "one authority-owned replay claim is required"
        );

        let mut unexpected_claim = false;
        let wrong_root = execute_claimed_read_on_roots(
            &mut roots,
            7,
            authenticated(
                "fedcba9876543210fedcba9876543210",
                7,
                "55555555-5555-4555-8555-555555555555",
            ),
            |_| {
                unexpected_claim = true;
                Result::<(), crate::sealed_dispatch::DispatchDenied>::Ok(())
            },
        );
        assert_eq!(wrong_root, Err(crate::sealed_dispatch::DispatchDenied));
        assert!(
            !unexpected_claim,
            "unissued rootRef must be denied before spending replay identity"
        );

        let mut stale_claim = false;
        let stale_epoch = execute_claimed_read_on_roots(
            &mut roots,
            7,
            authenticated(ROOT, 8, "66666666-6666-4666-8666-666666666666"),
            |_| {
                stale_claim = true;
                Result::<(), crate::sealed_dispatch::DispatchDenied>::Ok(())
            },
        );
        assert_eq!(stale_epoch, Err(crate::sealed_dispatch::DispatchDenied));
        assert!(
            !stale_claim,
            "stale expectedEpoch must be denied before spending replay identity"
        );
    }

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
