//! C4d dispatch contract against a sealed, preopened root; non-release.
//! No OS-protected bootstrap or client-facing constructor exists.
use crate::{canonical_request::decode_create_directory_frame, handle_mkdir::RootedDirectory};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchDenied;

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
///     used_requests: Default::default(), active: true,
/// };
/// ```
pub struct SealedDirectoryGrant {
    root_ref: String,
    expected_epoch: u64,
    rooted: RootedDirectory,
    used_requests: HashSet<String>,
    active: bool,
}

impl SealedDirectoryGrant {
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
        const MAX_REQUESTS_PER_EPOCH: usize = 1024;
        if !self.active || self.expected_epoch == 0 {
            return Err(DispatchDenied);
        }
        let request = decode_create_directory_frame(wire).map_err(|_| DispatchDenied)?;
        if request.root_ref() != self.root_ref
            || request.expected_epoch() != self.expected_epoch
            || self.used_requests.len() >= MAX_REQUESTS_PER_EPOCH
            || !self.used_requests.insert(request.request_id().to_owned())
        {
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
            used_requests: HashSet::new(),
            active: true,
        }
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
        assert_eq!(grant.used_requests.len(), 1024);
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
