//! Linux-only, non-authorizing acceptance of one kernel-connected C4d session.
//! The listener MUST already be bound by a protected service/socket manager
//! and set nonblocking. This module cannot establish provenance of its path.
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::sealed_dispatch::{DispatchDenied, SealedDirectoryGrant};
use crate::unix_peer::PreparedMcpClient;
use crate::unix_session::{
    read_authenticated_frame, read_prepared_client_frame, AuthenticatedFrame,
};

const MAX_DEADLINE: Duration = Duration::from_secs(5);

use crate::IdentityDenied;

/// Obtain a kernel-authenticated frame from exactly one prebound named
/// nonblocking listener. This only establishes principal+syntax, not policy.
fn accept_one_named_stream(
    listener: &UnixListener,
    deadline: Duration,
) -> Result<(UnixStream, Duration), IdentityDenied> {
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
        // Return only the OS-connected stream and the strictly remaining
        // deadline; identity and frame validation occur before observation.
        return Ok((stream, budget));
    }
}

fn read_one_named_authenticated(
    listener: &UnixListener,
    expected_uid: u32,
    expected_gid: u32,
    deadline: Duration,
) -> Result<AuthenticatedFrame, IdentityDenied> {
    let (stream, remaining) = accept_one_named_stream(listener, deadline)?;
    read_authenticated_frame(&stream, expected_uid, expected_gid, remaining)
}

/// Bind the prepared NSS peer to the kernel-named listener and revalidate
/// administrator policy BOTH before and after the potentially blocking read.
/// This returns observation only. It cannot mint a grant or dispatch I/O.
pub(crate) fn observe_one_named_prepared_with_checks(
    listener: &UnixListener,
    principal: PreparedMcpClient,
    expected_path: &Path,
    deadline: Duration,
    mut revalidate: impl FnMut() -> Result<(), IdentityDenied>,
) -> Result<(), IdentityDenied> {
    revalidate()?;
    crate::unix_activation::inspect_named_listener(listener.as_fd(), expected_path)?;
    let observed = accept_one_named_stream(listener, deadline)
        .and_then(|(stream, budget)| read_prepared_client_frame(&stream, &principal, budget))
        .map(|_| ());
    // Even a correctly authenticated request may be stale by the time its
    // complete frame arrives. An invalid frame must not hide epoch drift.
    revalidate()?;
    observed
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

/// One bounded binary response on the already accepted authenticated socket.
/// v1 header: [version=1, status=0 success or 1 denied, u32 BE length];
/// denial never includes pathname, error details or arbitrary bytes.
/// This primitive has no issuer constructor, response replay cache or MCP API.
fn write_bounded_read_reply(
    stream: &UnixStream,
    payload: Option<&[u8]>,
    expires: Instant,
) -> Result<(), DispatchDenied> {
    const MAX_REPLY_BYTES: usize = 1024 * 1024;
    let data = payload.unwrap_or(&[]);
    if data.len() > MAX_REPLY_BYTES {
        return Err(DispatchDenied);
    }
    let status = u8::from(payload.is_none());
    let mut header = [0u8; 6];
    header[0] = 1;
    header[1] = status;
    header[2..].copy_from_slice(&(data.len() as u32).to_be_bytes());
    for chunk in [&header[..], data] {
        let mut unsent = chunk;
        while !unsent.is_empty() {
            let remaining = expires.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(DispatchDenied);
            }
            let mut slot = libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
            // SAFETY: poll observes one live borrowed UnixStream descriptor,
            // and slot is a fully initialized stack object.
            let ready = unsafe { libc::poll(&mut slot, 1, millis.max(1)) };
            if ready == 0 {
                continue;
            }
            if ready < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(DispatchDenied);
            }
            if slot.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
                || slot.revents & libc::POLLOUT == 0
            {
                return Err(DispatchDenied);
            }
            // SAFETY: send reads at most unsent.len() bytes from an immutable
            // live slice; MSG_DONTWAIT cannot block and MSG_NOSIGNAL prevents
            // SIGPIPE on a disconnect. Neither call owns the socket.
            let sent = unsafe {
                libc::send(
                    stream.as_raw_fd(),
                    unsent.as_ptr().cast(),
                    unsent.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if sent < 0 {
                if matches!(
                    io::Error::last_os_error().kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                return Err(DispatchDenied);
            }
            if sent == 0 || Instant::now() >= expires {
                return Err(DispatchDenied);
            }
            unsent = &unsent[sent as usize..];
        }
    }
    Ok(())
}

/// Non-release, crate-private response experiment: one named OS-authenticated
/// read request, one bounded response, no grant fabrication. The currently
/// installed production binary has no issuer and never calls this function.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "non-release read responses have no issued service loop"
    )
)]
pub(crate) fn dispatch_one_named_read_reply(
    listener: &UnixListener,
    grant: &mut SealedDirectoryGrant,
    expected_uid: u32,
    expected_gid: u32,
    deadline: Duration,
    mut revalidate: impl FnMut(&mut SealedDirectoryGrant) -> Result<(), DispatchDenied>,
) -> Result<(), DispatchDenied> {
    // A valid kernel peer is not enough: this caller must possess the still-
    // current administrator-policy/root custody observation. Fail before
    // even accepting new work when the process generation has drifted.
    if revalidate(grant).is_err() {
        grant.revoke();
        return Err(DispatchDenied);
    }
    let (stream, budget) =
        accept_one_named_stream(listener, deadline).map_err(|_| DispatchDenied)?;
    let expires = Instant::now().checked_add(budget).ok_or(DispatchDenied)?;
    // The frame is accepted only after genuine kernel peer authentication
    // and complete canonical v1 parsing. No response on identity failure.
    let frame = read_authenticated_frame(&stream, expected_uid, expected_gid, budget)
        .map_err(|_| DispatchDenied)?;
    // The pathname namespace may change while reading from the socket.
    // A failed post-auth check sends no file bytes and revokes this grant.
    if revalidate(grant).is_err() {
        grant.revoke();
        let _ = write_bounded_read_reply(&stream, None, expires);
        return Err(DispatchDenied);
    }
    let result = grant.execute_authenticated_read(frame);
    // An already-open handle can remain valid after the administrator moves
    // its name elsewhere. Never send bytes acquired under a stale root.
    // This check is point-in-time; it is not a namespace lock or a substitute
    // for claim-to-operation linearization and outside-hardlink protection.
    if revalidate(grant).is_err() {
        grant.revoke();
        let _ = write_bounded_read_reply(&stream, None, expires);
        return Err(DispatchDenied);
    }
    let payload = result.as_ref().ok().map(Vec::as_slice);
    if write_bounded_read_reply(&stream, payload, expires).is_err() {
        grant.revoke(); // a partial/dropped reply must not revive this session
        return Err(DispatchDenied);
    }
    result.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    #[test]
    fn reply_writer_delivers_full_binary_megabyte_across_partial_socket_sends() {
        use std::thread;
        let (server, mut client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        let expected: Vec<u8> = (0..1024 * 1024).map(|index| (index % 251) as u8).collect();
        let peer = thread::spawn(move || {
            let mut header = [0u8; 6];
            client.read_exact(&mut header).unwrap();
            assert_eq!(header, [1, 0, 0, 16, 0, 0]);
            let mut received = vec![0u8; 1024 * 1024];
            client.read_exact(&mut received).unwrap();
            received
        });
        let sent = write_bounded_read_reply(
            &server,
            Some(&expected),
            Instant::now() + Duration::from_secs(5),
        );
        drop(server);
        assert_eq!(sent, Ok(()));
        assert_eq!(peer.join().unwrap(), expected);
    }

    #[test]
    fn reply_writer_has_bounded_deadline_and_refuses_oversize_before_sending() {
        use std::os::fd::AsRawFd;
        let (server, mut client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        let size: libc::c_int = 4096;
        // SAFETY: this sets a bounded send buffer for one valid owned socket;
        // the pointer and byte count exactly match the live integer.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    server.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        let too_large = vec![42u8; 1024 * 1024 + 1];
        assert_eq!(
            write_bounded_read_reply(
                &server,
                Some(&too_large),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(DispatchDenied),
        );
        client.set_nonblocking(true).unwrap();
        let mut untouched = [0u8; 1];
        assert_eq!(
            client.read(&mut untouched).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let bounded = vec![7u8; 1024 * 1024];
        let start = Instant::now();
        assert_eq!(
            write_bounded_read_reply(&server, Some(&bounded), start + Duration::from_millis(90)),
            Err(DispatchDenied),
            "a client that never reads must not stall the authority service",
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }

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
                    assert!(!changed.load(Ordering::SeqCst));
                    // The first validation must succeed before the worker
                    // can change policy. Never race the first state read.
                    prechecked.send(()).unwrap();
                    return Ok(());
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
