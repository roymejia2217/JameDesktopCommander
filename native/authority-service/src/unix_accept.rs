//! Linux-only, non-authorizing acceptance of one kernel-connected C4d session.
//! The listener MUST already be bound by a protected service/socket manager
//! and set nonblocking. This module cannot establish provenance of its path.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

use crate::unix_session::inspect_one_session;

const MAX_DEADLINE: Duration = Duration::from_secs(5);

use crate::IdentityDenied;

/// Observe at most one connection; returns no authority or filesystem handle.
/// Refuse blocking listener FDs. The deadline includes accept and frame read.
pub fn inspect_one_named_session(
    listener: &UnixListener,
    expected_uid: u32,
    expected_gid: u32,
    deadline: Duration,
) -> Result<(), IdentityDenied> {
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
        return inspect_one_session(&stream, expected_uid, expected_gid, budget);
    }
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
