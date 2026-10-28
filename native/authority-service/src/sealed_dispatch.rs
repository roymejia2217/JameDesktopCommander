//! C4d dispatch contract against a sealed, preopened root; non-release.
//! No OS-protected bootstrap or client-facing constructor exists.
use crate::{canonical_request::decode_create_directory_frame, handle_mkdir::RootedDirectory};
#[cfg(test)]
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchDenied;

// A production binary must never silently use process-local replay state.
// The durable admission variant is available internally but cannot be minted
// by a production OS-backed issuer yet. Test fixtures alone may attach it
// through the explicitly opt-in debug-only SQLite constructor.
#[derive(Default)]
enum ReplayAdmission {
    // Normal compilation has no durable issuer; default is always deny.
    #[default]
    Unavailable,
    // Production-compiled storage adapter. No production path may *construct*
    // a usable ledger until verified OS custody and publisher are implemented.
    #[cfg_attr(
        not(debug_assertions),
        expect(
            dead_code,
            reason = "release issuer intentionally cannot construct a durable admission until OS custody is proven"
        )
    )]
    Durable(jdc_authority_store::replay_ledger::ReplayClaimLedger),
    #[cfg(test)]
    SyntheticTestOnly(HashSet<[u8; 16]>),
}
impl ReplayAdmission {
    fn consume(&mut self, _request_id: [u8; 16]) -> Result<(), DispatchDenied> {
        match self {
            Self::Unavailable => Err(DispatchDenied),
            Self::Durable(ledger) => ledger.claim_once(_request_id).map_err(|_| DispatchDenied),
            #[cfg(test)]
            Self::SyntheticTestOnly(ids) => {
                if ids.len() >= 1024 || !ids.insert(_request_id) {
                    Err(DispatchDenied)
                } else {
                    Ok(())
                }
            }
        }
    }

    #[cfg(test)]
    fn synthetic_len(&self) -> usize {
        match self {
            Self::Unavailable | Self::Durable(_) => 0,
            Self::SyntheticTestOnly(ids) => ids.len(),
        }
    }
}

/// Cannot be instantiated by MCP clients or downstream crates.
/// Fields are private; there is intentionally NO production constructor.
///
/// An external consumer cannot fabricate a grant, even with its own Dir:
/// ```compile_fail
/// use jdc_authority_service::{sealed_dispatch::SealedDirectoryGrant, handle_mkdir::RootedDirectory};
/// use cap_std::{ambient_authority, fs::Dir};
/// let rooted = RootedDirectory::from_preopened(
///     Dir::open_ambient_dir(".", ambient_authority()).unwrap());
/// let _grant = SealedDirectoryGrant {
///     root_ref: String::new(), expected_epoch: 7, rooted,
///     replay: Default::default(), active: true,
/// };
/// ```
pub struct SealedDirectoryGrant {
    root_ref: String,
    expected_epoch: u64,
    rooted: RootedDirectory,
    // No volatile replay fallback in non-test builds. A future issuer must
    // provide a trusted durable claimer before operational dispatch is enabled.
    replay: ReplayAdmission,
    active: bool,
    #[cfg(all(target_os = "linux", not(test)))]
    epoch_monitor: Option<crate::linux_policy_epoch_monitor::PolicyEpochMonitor>,
    #[cfg(all(target_os = "linux", not(test)))]
    policy_digest: [u8; 32],
}

impl SealedDirectoryGrant {
    /// Bind the OS-pinned root from a separately attested administrative policy.
    /// This constructor cannot issue execution rights by itself: the replay
    /// admission is deliberately Unavailable until a trusted durable store is
    /// independently bound to the same epoch, policy and service identity.
    pub(crate) fn from_issuer_policy(
        policy: &crate::issuer_policy::IssuerPolicy,
        root_ref: &str,
    ) -> Result<Self, DispatchDenied> {
        if policy.epoch() == 0 {
            return Err(DispatchDenied);
        }
        // The normal Linux build must reobserve independently root-owned
        // policy+witness; a self-supplied policy or epoch is insufficient.
        #[cfg(all(target_os = "linux", not(test)))]
        let mut monitor = {
            let mut observed =
                crate::linux_policy_epoch_monitor::PolicyEpochMonitor::from_current_os_attested()
                    .map_err(|_| DispatchDenied)?;
            observed
                .revalidate_issued_policy(policy.epoch(), policy.digest())
                .map_err(|_| DispatchDenied)?;
            observed
        };
        let rooted = policy.open_root(root_ref).map_err(|_| DispatchDenied)?;
        #[cfg(all(target_os = "linux", not(test)))]
        monitor
            .revalidate_issued_policy(policy.epoch(), policy.digest())
            .map_err(|_| DispatchDenied)?;
        Ok(Self {
            root_ref: root_ref.to_owned(),
            expected_epoch: policy.epoch(),
            rooted,
            replay: ReplayAdmission::Unavailable,
            active: true,
            #[cfg(all(target_os = "linux", not(test)))]
            epoch_monitor: Some(monitor),
            #[cfg(all(target_os = "linux", not(test)))]
            policy_digest: *policy.digest(),
        })
    }

    /// The only Linux production-compiled dispatch entry takes a frame made
    /// by a checked kernel peer, never raw untrusted caller bytes.
    /// This remains non-authorizing without a protected root/epoch bootstrap.
    #[cfg(target_os = "linux")]
    pub(crate) fn execute_authenticated_c4d(
        &mut self,
        frame: crate::unix_session::AuthenticatedFrame,
    ) -> Result<(), DispatchDenied> {
        self.execute_c4d_impl(&frame.into_wire())
    }

    /// Raw-input dispatch exists strictly for isolated adversarial unit tests.
    #[cfg(test)]
    fn execute_c4d(&mut self, wire: &[u8]) -> Result<(), DispatchDenied> {
        self.execute_c4d_impl(wire)
    }

    /// Validate C4d data, rootRef, epoch and one-shot request identity.
    #[cfg(any(target_os = "linux", test))]
    fn execute_c4d_impl(&mut self, wire: &[u8]) -> Result<(), DispatchDenied> {
        if !self.active || self.expected_epoch == 0 {
            return Err(DispatchDenied);
        }
        // Must precede request-ID consumption and *all* filesystem mutation.
        // In normal Linux builds an unprovisioned monitor ALWAYS denies.
        #[cfg(all(target_os = "linux", not(test)))]
        {
            let witnessed = self.epoch_monitor.as_mut().ok_or(DispatchDenied)?;
            if witnessed
                .revalidate_issued_policy(self.expected_epoch, &self.policy_digest)
                .is_err()
            {
                self.active = false; // sticky for this sealed capability
                return Err(DispatchDenied);
            }
        }
        let request = decode_create_directory_frame(wire).map_err(|_| DispatchDenied)?;
        if request.root_ref() != self.root_ref || request.expected_epoch() != self.expected_epoch {
            return Err(DispatchDenied);
        }
        // A ledger write/validation failure is indistinguishable from storage
        // rollback or corruption at this boundary. In a durable session it
        // permanently revokes the grant rather than implicitly re-admitting
        // when the same path begins working again.
        if self.replay.consume(request.request_id_bytes()).is_err() {
            if matches!(self.replay, ReplayAdmission::Durable(_)) {
                self.replay = ReplayAdmission::Unavailable;
                self.active = false;
            }
            return Err(DispatchDenied);
        }
        // Consume the request ID before I/O: a failed/partial I/O is not
        // silently retried against a changed filesystem namespace.
        self.rooted
            .create_descendant(request.relative_path())
            .map_err(|_| DispatchDenied)
    }
    pub fn revoke(&mut self) {
        self.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::{ambient_authority, fs::Dir};
    use std::path::Path;
    const ROOT: &str = "0123456789abcdef0123456789abcdef";
    const ID: &str = "11111111-1111-4111-8111-111111111111";
    fn wire(root: &str, epoch: u64, request: &str, relative: &str) -> Vec<u8> {
        let body = format!(
            r#"{{"version":1,"kind":"create-directory","requestId":"{request}","expectedEpoch":"{epoch}","rootRef":"{root}","relativePath":"{relative}"}}"#
        );
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(body.as_bytes());
        out
    }
    fn fixture(root: &Path) -> SealedDirectoryGrant {
        SealedDirectoryGrant {
            root_ref: ROOT.to_owned(),
            expected_epoch: 7,
            rooted: RootedDirectory::from_preopened(
                Dir::open_ambient_dir(root, ambient_authority()).unwrap(),
            ),
            replay: ReplayAdmission::SyntheticTestOnly(HashSet::new()),
            active: true,
        }
    }
    #[cfg(debug_assertions)] // The offline-fixture constructor is unavailable in release builds.
    #[test]
    fn offline_sqlite_replay_claim_is_consumed_before_actual_mkdir_and_survives_restart() {
        use jdc_authority_store::replay_ledger::ReplayClaimLedger;
        use rusqlite::{Connection, OpenFlags};
        let f = tempfile::tempdir().unwrap();
        let root = f.path().join("allowed");
        std::fs::create_dir(&root).unwrap();
        let db_path = f.path().join("claims.sqlite3");
        let db = Connection::open(&db_path).unwrap();
        db.execute_batch(
            "PRAGMA application_id=0x4A44434C; PRAGMA user_version=1;
             CREATE TABLE replay_claims (epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)=16), PRIMARY KEY(epoch,request)) WITHOUT ROWID"
        ).unwrap();
        drop(db);
        let open_ledger = || {
            let db =
                Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
            ReplayClaimLedger::from_offline_fixture(db, 7).unwrap()
        };
        let mut first = fixture(&root);
        first.replay = ReplayAdmission::Durable(open_ledger());
        let good = wire(ROOT, 7, ID, "one");
        assert_eq!(first.execute_c4d(&good), Ok(()));
        assert!(root.join("one").is_dir());
        assert_eq!(first.execute_c4d(&good), Err(DispatchDenied));
        drop(first);
        let mut restart = fixture(&root);
        restart.replay = ReplayAdmission::Durable(open_ledger());
        assert_eq!(
            restart.execute_c4d(&wire(ROOT, 7, ID, "other")),
            Err(DispatchDenied)
        );
        assert!(!root.join("other").exists());
        // A replay failure poisons only the affected grant; no implicit
        // recovery is permitted on that session. Recreate the grant explicitly
        // against the same persistent ledger to test fresh valid operations.
        assert!(!restart.active);
        drop(restart);
        let mut restart = fixture(&root);
        restart.replay = ReplayAdmission::Durable(open_ledger());
        assert_eq!(
            restart.execute_c4d(&wire(
                ROOT,
                7,
                "22222222-2222-4222-8222-222222222222",
                "new"
            )),
            Ok(())
        );
        assert!(root.join("new").is_dir());
        assert_eq!(
            restart.execute_c4d(&wire(
                ROOT,
                8,
                "33333333-3333-4333-8333-333333333333",
                "stale"
            )),
            Err(DispatchDenied)
        );
        assert!(!root.join("stale").exists());
        // Durability precedes the filesystem operation. An OS error must not
        // permit a second attempt with the same ID after namespace changes.
        std::fs::write(root.join("occupied"), b"NOT_DIRECTORY").unwrap();
        let failed_id = "44444444-4444-4444-8444-444444444444";
        assert_eq!(
            restart.execute_c4d(&wire(ROOT, 7, failed_id, "occupied/child")),
            Err(DispatchDenied)
        );
        std::fs::remove_file(root.join("occupied")).unwrap();
        assert_eq!(
            restart.execute_c4d(&wire(ROOT, 7, failed_id, "created_after_failed_io")),
            Err(DispatchDenied)
        );
        assert!(!root.join("created_after_failed_io").exists());
        assert!(!restart.active);
        drop(restart);
        let mut restart = fixture(&root);
        restart.replay = ReplayAdmission::Durable(open_ledger());
        // Bad policy data cannot spend a valid replay identity.
        let fresh = "55555555-5555-4555-8555-555555555555";
        assert_eq!(
            restart.execute_c4d(&wire(
                "00000000000000000000000000000000",
                7,
                fresh,
                "forged"
            )),
            Err(DispatchDenied)
        );
        assert_eq!(
            restart.execute_c4d(&wire(ROOT, 7, fresh, "valid_after_forgery")),
            Ok(())
        );
        assert!(root.join("valid_after_forgery").is_dir());
        // The ledger schema must be validated again inside the same durable
        // claim transaction; a foreign object causes a hard denial.
        let tamper = Connection::open(&db_path).unwrap();
        tamper
            .execute_batch("CREATE TABLE injected (x TEXT)")
            .unwrap();
        assert_eq!(
            restart.execute_c4d(&wire(
                ROOT,
                7,
                "66666666-6666-4666-8666-666666666666",
                "tampered"
            )),
            Err(DispatchDenied)
        );
        assert!(!root.join("tampered").exists());
        tamper.execute_batch("DROP TABLE injected").unwrap();
        // A previously failed durable authority must never auto-regrant
        // permissions just because its backing SQLite appears healthy again.
        assert_eq!(
            restart.execute_c4d(&wire(
                ROOT,
                7,
                "77777777-7777-4777-8777-777777777777",
                "after_repair"
            )),
            Err(DispatchDenied)
        );
        assert!(!root.join("after_repair").exists());
    }

    #[test]
    fn os_root_issued_from_admin_policy_cannot_dispatch_without_durable_replay() {
        let f = tempfile::tempdir().unwrap();
        let allowed = f.path().join("allowed");
        let outside = f.path().join("outside");
        std::fs::create_dir(&allowed).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let sentinel = outside.join("secret");
        std::fs::write(&sentinel, b"NEVER_CHANGED").unwrap();
        let json_path = serde_json::to_string(allowed.to_str().unwrap()).unwrap();
        let policy_bytes = format!(
            r#"{{"version":1,"mode":"restricted","roots":[{{"rootRef":"{ROOT}","absolutePath":{json_path}}}]}}"#
        );
        let policy = crate::issuer_policy::IssuerPolicy::decode_exact_for_test(
            policy_bytes.as_bytes(),
            9,
            [1; 32],
        )
        .unwrap();
        let mut grant = SealedDirectoryGrant::from_issuer_policy(&policy, ROOT).unwrap();
        assert_eq!(grant.expected_epoch, 9);
        assert_eq!(
            grant.execute_c4d(&wire(ROOT, 9, ID, "blocked")),
            Err(DispatchDenied)
        );
        assert!(!allowed.join("blocked").exists());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"NEVER_CHANGED");
        assert!(SealedDirectoryGrant::from_issuer_policy(
            &policy,
            "00000000000000000000000000000000"
        )
        .is_err());
    }

    #[test]
    fn canonical_unicode_and_internal_spaces_execute_inside_pinned_root() {
        let f = tempfile::tempdir().unwrap();
        let inside = f.path().join("allowed");
        let outside = f.path().join("outside");
        std::fs::create_dir(&inside).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let sentinel = outside.join("sentinel");
        std::fs::write(&sentinel, b"NEVER_CHANGED").unwrap();
        let mut grant = fixture(&inside);
        let frame = wire(ROOT, 7, ID, "科研/mi carpeta");
        // The strict C4d parser already accepts this exact Unicode spelling.
        assert!(decode_create_directory_frame(&frame).is_ok());
        assert_eq!(grant.execute_c4d(&frame), Ok(()));
        assert!(inside.join("科研/mi carpeta").is_dir());
        assert!(!outside.join("科研").exists());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"NEVER_CHANGED");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn named_socket_dispatch_requires_kernel_identity_and_sealed_grant_without_raw_wire_bypass() {
        use std::{
            fs,
            io::Write,
            net::Shutdown,
            os::unix::net::{UnixListener, UnixStream},
            time::Duration,
        };
        let base = tempfile::tempdir().unwrap();
        let allowed = base.path().join("allowed");
        let outside = base.path().join("outside");
        fs::create_dir(&allowed).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"UNMODIFIED").unwrap();
        let socket = base.path().join("authority.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert_ne!(uid, 0);
        assert_ne!(gid, 0);
        let mut grant = fixture(&allowed);
        let mut client = UnixStream::connect(&socket).unwrap();
        client
            .write_all(&wire(ROOT, 7, ID, "authenticated"))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            crate::unix_accept::dispatch_one_named_c4d(
                &listener,
                &mut grant,
                uid.wrapping_add(1),
                gid,
                Duration::from_secs(1)
            ),
            Err(DispatchDenied),
            "foreign identity must deny before mutation"
        );
        assert!(!allowed.join("authenticated").exists());
        let mut client = UnixStream::connect(&socket).unwrap();
        client
            .write_all(&wire(ROOT, 7, ID, "authenticated"))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            crate::unix_accept::dispatch_one_named_c4d(
                &listener,
                &mut grant,
                uid,
                gid,
                Duration::from_secs(1)
            ),
            Ok(()),
            "kernel-authenticated named request must dispatch"
        );
        assert!(allowed.join("authenticated").is_dir());
        let mut replay = UnixStream::connect(&socket).unwrap();
        replay.write_all(&wire(ROOT, 7, ID, "changed")).unwrap();
        replay.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            crate::unix_accept::dispatch_one_named_c4d(
                &listener,
                &mut grant,
                uid,
                gid,
                Duration::from_secs(1)
            ),
            Err(DispatchDenied),
            "consumed request identity must reject replay"
        );
        assert!(!allowed.join("changed").exists());
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"UNMODIFIED");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn connected_kernel_peer_can_dispatch_once_only_with_sealed_root_and_matching_epoch() {
        use std::io::Write;
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let f = tempfile::tempdir().unwrap();
        let inside = f.path().join("inside");
        let outside = f.path().join("outside");
        std::fs::create_dir(&inside).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"KEEP_EXTERNAL_BYTES").unwrap();
        let mut grant = fixture(&inside);
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert_ne!(uid, 0, "positive kernel-identity fixture must be nonroot");
        assert_ne!(gid, 0);

        fn send(wire: &[u8]) -> UnixStream {
            let (mut client, service) = UnixStream::pair().unwrap();
            client.write_all(wire).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            service
        }
        let valid = wire(ROOT, 7, ID, "科研/client-folder");
        let connection = send(&valid);
        let verified = crate::unix_session::read_authenticated_frame(
            &connection,
            uid,
            gid,
            Duration::from_secs(1),
        )
        .expect("kernel-authenticated complete C4d frame");
        assert_eq!(grant.execute_authenticated_c4d(verified), Ok(()));
        assert!(inside.join("科研/client-folder").is_dir());

        // A different connection cannot replay a request against this grant.
        let replay = send(&valid);
        let verified = crate::unix_session::read_authenticated_frame(
            &replay,
            uid,
            gid,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            grant.execute_authenticated_c4d(verified),
            Err(DispatchDenied)
        );
        // Forging expected service identity is denied before dispatch.
        let foreign = send(&wire(
            ROOT,
            7,
            "22222222-2222-4222-8222-222222222222",
            "foreign",
        ));
        assert!(crate::unix_session::read_authenticated_frame(
            &foreign,
            uid.wrapping_add(1),
            gid,
            Duration::from_millis(100),
        )
        .is_err());
        assert!(!inside.join("foreign").exists());

        let stale = send(&wire(
            ROOT,
            8,
            "33333333-3333-4333-8333-333333333333",
            "stale",
        ));
        let verified =
            crate::unix_session::read_authenticated_frame(&stale, uid, gid, Duration::from_secs(1))
                .unwrap();
        assert_eq!(
            grant.execute_authenticated_c4d(verified),
            Err(DispatchDenied)
        );
        assert!(!inside.join("stale").exists());

        assert!(!outside.join("科研").exists());
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"KEEP_EXTERNAL_BYTES"
        );
    }

    #[test]
    fn no_issued_durable_replay_authority_denies_without_creating_files() {
        let f = tempfile::tempdir().unwrap();
        let inside = f.path().join("inside");
        std::fs::create_dir(&inside).unwrap();
        let mut grant = fixture(&inside);
        grant.replay = ReplayAdmission::default();
        assert_eq!(
            grant.execute_c4d(&wire(ROOT, 7, ID, "forbidden")),
            Err(DispatchDenied)
        );
        assert!(!inside.join("forbidden").exists());
        assert_eq!(
            grant.execute_c4d(&wire(ROOT, 7, ID, "again")),
            Err(DispatchDenied)
        );
        assert!(!inside.join("again").exists());
    }
    #[test]
    fn matching_root_epoch_creates_only_inside_then_replay_denies() {
        let f = tempfile::tempdir().unwrap();
        let inside = f.path().join("inside");
        let outside = f.path().join("outside");
        std::fs::create_dir(&inside).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let mut grant = fixture(&inside);
        let first = wire(ROOT, 7, ID, "one/two");
        assert_eq!(grant.execute_c4d(&first), Ok(()));
        assert!(inside.join("one/two").is_dir());
        assert_eq!(grant.execute_c4d(&first), Err(DispatchDenied));
        assert!(!outside.join("one").exists());
    }
    #[test]
    fn changed_path_with_reused_id_and_failed_io_retry_remain_denied() {
        let f = tempfile::tempdir().unwrap();
        let inside = f.path().join("inside");
        std::fs::create_dir(&inside).unwrap();
        let mut grant = fixture(&inside);
        let file = inside.join("occupied");
        std::fs::write(&file, b"SAFE_FILE").unwrap();
        assert_eq!(
            grant.execute_c4d(&wire(ROOT, 7, ID, "occupied/child")),
            Err(DispatchDenied)
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"SAFE_FILE");
        std::fs::remove_file(&file).unwrap();
        assert_eq!(
            grant.execute_c4d(&wire(ROOT, 7, ID, "new/child")),
            Err(DispatchDenied)
        );
        assert!(!inside.join("new").exists());
    }

    #[test]
    fn full_request_ledger_fails_closed_without_eviction_or_implicit_regrant() {
        let f = tempfile::tempdir().unwrap();
        let inside = f.path().join("inside");
        std::fs::create_dir(&inside).unwrap();
        let mut grant = fixture(&inside);
        for n in 0..1024u32 {
            let id = format!("11111111-1111-4111-8111-{n:012x}");
            assert_eq!(grant.execute_c4d(&wire(ROOT, 7, &id, "existing")), Ok(()));
        }
        assert_eq!(grant.replay.synthetic_len(), 1024);
        let next = "11111111-1111-4111-8111-ffffffffffff";
        assert_eq!(
            grant.execute_c4d(&wire(ROOT, 7, next, "forbidden")),
            Err(DispatchDenied)
        );
        assert!(!inside.join("forbidden").exists());
    }

    #[test]
    fn in_memory_replay_barrier_does_not_survive_restart_without_trusted_store() {
        let f = tempfile::tempdir().unwrap();
        let inside = f.path().join("inside");
        std::fs::create_dir(&inside).unwrap();
        let request = wire(ROOT, 7, ID, "test");
        assert_eq!(fixture(&inside).execute_c4d(&request), Ok(()));
        assert_eq!(
            fixture(&inside).execute_c4d(&request),
            Ok(()),
            "NEGATIVE PROOF: synthetic grant does not persist request replay protection"
        );
    }

    #[test]
    fn forged_root_stale_epoch_and_revocation_never_mutate() {
        let f = tempfile::tempdir().unwrap();
        let inside = f.path().join("inside");
        std::fs::create_dir(&inside).unwrap();
        let mut grant = fixture(&inside);
        let forged = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            grant.execute_c4d(&wire(forged, 7, ID, "forged")),
            Err(DispatchDenied)
        );
        assert_eq!(
            grant.execute_c4d(&wire(ROOT, 8, ID, "stale")),
            Err(DispatchDenied)
        );
        assert!(!inside.join("forged").exists());
        assert!(!inside.join("stale").exists());
        grant.revoke();
        assert_eq!(
            grant.execute_c4d(&wire(ROOT, 7, ID, "revoked")),
            Err(DispatchDenied)
        );
        assert!(!inside.join("revoked").exists());
    }
}
