//! Linux-only, non-authorizing acceptance of one kernel-connected C4d session.
//! The listener MUST already be bound by a protected service/socket manager
//! and set nonblocking. This module cannot establish provenance of its path.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

use crate::sealed_dispatch::{DispatchDenied, SealedDirectoryGrant};
use crate::unix_session::{read_authenticated_frame, AuthenticatedFrame};

const MAX_DEADLINE: Duration = Duration::from_secs(5);

use crate::IdentityDenied;

/// Obtain a kernel-authenticated frame from exactly one prebound named
/// nonblocking listener. This only establishes principal+syntax, not policy.
fn read_one_named_authenticated(
    listener: &UnixListener,
    expected_uid: u32,
    expected_gid: u32,
    deadline: Duration,
) -> Result<AuthenticatedFrame, IdentityDenied> {
    if deadline.is_zero() || deadline > MAX_DEADLINE {
        return Err(IdentityDenied);
    }
    // The protected service is responsible for socket path custody and
    // the expected UID/GID. A pathname or mode snapshot is not authorization.
    if listener
        .local_addr()
        .map_err(|_| IdentityDenied)?
        .as_pathname()
        .is_none()
    {
        return Err(IdentityDenied);
    }
    let raw = listener.as_raw_fd();
    // Require the listener to be configured nonblocking BEFORE this call.
    // accept4(SOCK_NONBLOCK) alone does not make a blocking listener safe.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 || (flags & libc::O_NONBLOCK) == 0 {
        return Err(IdentityDenied);
    }
    let expires = Instant::now().checked_add(deadline).ok_or(IdentityDenied)?;
    loop {
        let remaining = expires.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IdentityDenied);
        }
        let mut slot = libc::pollfd {
            fd: raw,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: borrowed listener FD stays alive for this invocation; poll
        // only accesses this initialized stack pollfd.
        let ready = unsafe { libc::poll(&mut slot, 1, millis.max(1)) };
        if ready == 0 {
            continue;
        }
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(IdentityDenied);
        }
        if slot.revents & libc::POLLIN == 0 {
            return Err(IdentityDenied);
        }
        // SAFETY: valid AF_UNIX listener descriptor, no sockaddr destination;
        // the kernel returns a uniquely owned FD or an error. CLOEXEC and
        // NONBLOCK protect the accepted FD; the listener was checked above.
        let accepted = unsafe {
            libc::accept4(
                raw,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            )
        };
        if accepted < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(IdentityDenied);
        }
        // SAFETY: accept4 returned one new owned FD not referenced elsewhere.
        let stream = unsafe { UnixStream::from_raw_fd(accepted) };
        let budget = expires.saturating_duration_since(Instant::now());
        if budget.is_zero() {
            return Err(IdentityDenied);
        }
        // This call only verifies kernel identity and request *syntax*.
        // It does not return or operate on a privileged filesystem handle.
        return read_authenticated_frame(&stream, expected_uid, expected_gid, budget);
    }
}

/// Observation-only compatibility interface; cannot create a sealed grant.
pub fn inspect_one_named_session(
    listener: &UnixListener,
    expected_uid: u32,
    expected_gid: u32,
    deadline: Duration,
) -> Result<(), IdentityDenied> {
    read_one_named_authenticated(listener, expected_uid, expected_gid, deadline).map(|_| ())
}

/// End-to-end authenticated Linux C4d dispatch proof. The caller cannot
/// fabricate SealedDirectoryGrant or AuthenticatedFrame from an MCP request.
/// Still not a service: there is no approved root bootstrap or policy owner.
pub fn dispatch_one_named_c4d(
    listener: &UnixListener,
    grant: &mut SealedDirectoryGrant,
    expected_uid: u32,
    expected_gid: u32,
    deadline: Duration,
) -> Result<(), DispatchDenied> {
    let frame = read_one_named_authenticated(listener, expected_uid, expected_gid, deadline)
        .map_err(|_| DispatchDenied)?;
    grant.execute_authenticated_c4d(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    fn ids() -> (u32, u32) {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert_ne!(uid, 0, "positive control requires nonroot Linux runner");
        assert_ne!(gid, 0, "positive control requires nonroot group");
        (uid, gid)
    }
    fn wire() -> Vec<u8> {
        let json = br#"{"version":1,"kind":"create-directory","requestId":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","rootRef":"0123456789abcdef0123456789abcdef","relativePath":"safe"}"#;
        let mut result = (json.len() as u32).to_be_bytes().to_vec();
        result.extend_from_slice(json);
        result
    }

    fn fixture() -> (tempfile::TempDir, UnixListener) {
        let dir = tempfile::tempdir().expect("create owned private directory");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .expect("set private parent permissions");
        let path = dir.path().join("authority.sock");
        let listener = UnixListener::bind(&path).expect("bind true AF_UNIX named endpoint");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restrict named socket permissions");
        listener
            .set_nonblocking(true)
            .expect("nonblocking accept precondition");
        assert_eq!(
            fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        (dir, listener)
    }

    #[test]
    fn prepared_issuer_listener_denies_policy_revocation_during_frame_read() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        };
        use std::thread;
        let (dir, listener) = fixture();
        let path = dir.path().join("authority.sock");
        let client =
            crate::unix_peer::PreparedMcpClient::from_current_unprivileged_os_account_for_test()
                .unwrap();
        let changed = Arc::new(AtomicBool::new(false));
        let revoked = Arc::clone(&changed);
        let (prechecked, start_client) = mpsc::sync_channel(0);
        let worker = thread::spawn(move || {
            start_client.recv().unwrap();
            revoked.store(true, Ordering::SeqCst);
            let mut sender = UnixStream::connect(path).unwrap();
            sender.write_all(&wire()).unwrap();
            sender.shutdown(Shutdown::Write).unwrap();
        });
        let mut validations = 0;
        let decision = observe_one_named_prepared_with_checks(
            &listener,
            client,
            &dir.path().join("authority.sock"),
            Duration::from_secs(2),
            || {
                validations += 1;
                if validations == 1 {
                    prechecked.send(()).unwrap();
                }
                if changed.load(Ordering::SeqCst) {
                    Err(IdentityDenied)
                } else {
                    Ok(())
                }
            },
        );
        worker.join().unwrap();
        assert_eq!(decision, Err(IdentityDenied));
        assert_eq!(
            validations, 2,
            "policy must be rechecked after the OS-authenticated frame"
        );
    }

    #[test]
    fn prepared_issuer_listener_accepts_genuine_peer_only_as_data() {
        let (dir, listener) = fixture();
        let path = dir.path().join("authority.sock");
        let client =
            crate::unix_peer::PreparedMcpClient::from_current_unprivileged_os_account_for_test()
                .unwrap();
        let mut sender = UnixStream::connect(&path).unwrap();
        sender.write_all(&wire()).unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
        let mut validations = 0;
        assert_eq!(
            observe_one_named_prepared_with_checks(
                &listener,
                client,
                &path,
                Duration::from_secs(2),
                || {
                    validations += 1;
                    Ok(())
                }
            ),
            Ok(())
        );
        assert_eq!(validations, 2);
        assert_eq!(
            observe_one_named_prepared_with_checks(
                &listener,
                client,
                &dir.path().join("other.sock"),
                Duration::from_millis(20),
                || Ok(())
            ),
            Err(IdentityDenied),
            "a different named listener is denied even with matching peer UID/GID"
        );
    }

    #[test]
    fn valid_named_socket_connection_is_only_observed_not_authorized() {
        let (dir, listener) = fixture();
        let (uid, gid) = ids();
        let mut sender = UnixStream::connect(dir.path().join("authority.sock")).unwrap();
        sender.write_all(&wire()).unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            inspect_one_named_session(&listener, uid, gid, Duration::from_secs(1)),
            Ok(()),
        );
    }

    #[test]
    fn no_peer_and_blocking_listener_fail_closed_with_bounded_wait() {
        let (_dir, listener) = fixture();
        let (uid, gid) = ids();
        let started = Instant::now();
        assert_eq!(
            inspect_one_named_session(&listener, uid, gid, Duration::from_millis(60)),
            Err(IdentityDenied),
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "accept deadline violated"
        );
        listener.set_nonblocking(false).unwrap();
        let started = Instant::now();
        assert_eq!(
            inspect_one_named_session(&listener, uid, gid, Duration::from_secs(1)),
            Err(IdentityDenied),
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "blocking listener must be rejected before accept"
        );
    }
    #[test]
    fn invalid_kernel_principal_and_framing_are_denied_over_named_socket() {
        let (dir, listener) = fixture();
        let (uid, gid) = ids();
        let path = dir.path().join("authority.sock");
        let mut sender = UnixStream::connect(&path).unwrap();
        sender.write_all(&wire()).unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            inspect_one_named_session(&listener, uid.wrapping_add(1), gid, Duration::from_secs(1)),
            Err(IdentityDenied),
        );
        let mut second = UnixStream::connect(&path).unwrap();
        second.write_all(b"\0\0\0\x02[]").unwrap();
        second.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            inspect_one_named_session(&listener, uid, gid, Duration::from_secs(1)),
            Err(IdentityDenied),
        );
    }
}
