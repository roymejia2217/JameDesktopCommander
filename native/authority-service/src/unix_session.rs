//! Non-authorizing, Linux-only one-shot *connected* AF_UNIX session inspection.
//! No listener, privilege, IPC reply, or filesystem operation is introduced.
//! Expected account MUST come from protected service configuration, not input.
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::canonical_request::validate_request_frame;
use crate::frame_reader::read_one_frame;
use crate::peer_contract::validate_expected_kernel_peer;
use crate::unix_peer::observe_connected_peer;
use crate::IdentityDenied;

const MAX_SESSION_DEADLINE: Duration = Duration::from_secs(5);

/// Unforgeable within the crate: constructed only after a real kernel
/// SO_PEERCRED check, a complete canonical frame and the absolute deadline.
/// This is identity evidence, NOT an independent policy or filesystem grant.
pub(crate) struct AuthenticatedFrame {
    wire: Vec<u8>,
}

impl AuthenticatedFrame {
    pub(crate) fn into_wire(self) -> Vec<u8> {
        self.wire
    }
}

struct DeadlineReader<'a> {
    stream: &'a UnixStream,
    expires: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let remaining = self.expires.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "session deadline"));
            }
            // poll may round up to a whole millisecond. The monotonic
            // deadline is rechecked before and after the nonblocking recv.
            let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
            let mut slot = libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: slot is a live stack pollfd and only this single
            // connected borrowed socket is observed. poll never owns it.
            let ready = unsafe { libc::poll(&mut slot, 1, millis.max(1)) };
            if ready == 0 {
                continue;
            }
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if slot.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("invalid session socket"));
            }
            if Instant::now() >= self.expires {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "session deadline"));
            }
            // SAFETY: recv writes no more than buffer.len() bytes; MSG_DONTWAIT
            // does not modify shared socket flags or descriptor ownership.
            let bytes = unsafe {
                libc::recv(
                    self.stream.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if bytes >= 0 {
                if Instant::now() >= self.expires {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "session deadline"));
                }
                return Ok(bytes as usize);
            }
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(error);
        }
    }
}

/// Return a single, typed frame only after kernel peer authentication.
/// Caller must separately supply a protected epoch and a sealed root handle.
pub(crate) fn read_authenticated_frame(
    stream: &UnixStream,
    expected_uid: u32,
    expected_gid: u32,
    deadline: Duration,
) -> Result<AuthenticatedFrame, IdentityDenied> {
    if deadline.is_zero() || deadline > MAX_SESSION_DEADLINE {
        return Err(IdentityDenied);
    }
    // These expected IDs MUST originate from independently protected service
    // policy, never a request or environment variable. No blocking NSS lookup
    // is permitted in the per-request path.
    let expires = Instant::now().checked_add(deadline).ok_or(IdentityDenied)?;
    let peer = observe_connected_peer(stream.as_fd())?;
    validate_expected_kernel_peer(
        peer.pid(),
        peer.uid(),
        peer.gid(),
        expected_uid,
        expected_gid,
    )?;
    let mut reader = DeadlineReader { stream, expires };
    let wire = read_one_frame(&mut reader).map_err(|_| IdentityDenied)?;
    validate_request_frame(&wire).map_err(|_| IdentityDenied)?;
    // Identity and syntax evidence only; no root authority follows.
    Ok(AuthenticatedFrame { wire })
}

/// Backward-compatible observation-only API. Do not authorize from Ok(()).
pub fn inspect_one_session(
    stream: &UnixStream,
    expected_uid: u32,
    expected_gid: u32,
    deadline: Duration,
) -> Result<(), IdentityDenied> {
    read_authenticated_frame(stream, expected_uid, expected_gid, deadline).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::Shutdown;
    use std::time::Instant;

    fn expected_test_ids() -> (u32, u32) {
        // Only an unprivileged kernel positive control for this test.
        // Production IDs must come from independently protected policy.
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert_ne!(uid, 0, "non-root kernel positive control required");
        assert_ne!(gid, 0, "non-root kernel group positive control required");
        (uid, gid)
    }

    fn valid_request() -> Vec<u8> {
        let bytes = br#"{"version":1,"kind":"create-directory","requestId":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","rootRef":"0123456789abcdef0123456789abcdef","relativePath":"safe"}"#;
        let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(bytes);
        frame
    }
    #[test]
    fn kernel_verified_peer_with_complete_canonical_frame_is_observable_only() {
        let (uid, gid) = expected_test_ids();
        let (mut sender, receiver) = UnixStream::pair().expect("kernel stream socketpair");
        sender
            .write_all(&valid_request())
            .expect("write canonical C4d");
        sender
            .shutdown(Shutdown::Write)
            .expect("client signals one-frame EOF");
        assert_eq!(
            inspect_one_session(&receiver, uid, gid, Duration::from_secs(1)),
            Ok(()),
            "positive test must not be satisfied by blanket denial",
        );
    }

    #[test]
    fn foreign_or_root_account_is_rejected_before_reading_payload() {
        let (sender, receiver) = UnixStream::pair().expect("kernel socketpair");
        let (uid, gid) = expected_test_ids();
        let start = Instant::now();
        for pair in [
            (0, gid),
            (uid, 0),
            (uid.wrapping_add(1), gid),
            (uid, gid.wrapping_add(1)),
        ] {
            assert_eq!(
                inspect_one_session(&receiver, pair.0, pair.1, Duration::from_millis(100)),
                Err(IdentityDenied),
            );
        }
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "reject identity before waiting for bytes"
        );
        drop(sender);
    }

    #[test]
    fn incomplete_frame_and_client_without_eof_cannot_stall_beyond_deadline() {
        let (uid, gid) = expected_test_ids();
        for bytes in [vec![0, 0], valid_request()] {
            let (mut sender, receiver) = UnixStream::pair().expect("kernel stream");
            sender
                .write_all(&bytes)
                .expect("write deliberate partial session");
            // Keep the write half OPEN, forcing a real kernel read stall.
            let start = Instant::now();
            assert_eq!(
                inspect_one_session(&receiver, uid, gid, Duration::from_millis(60)),
                Err(IdentityDenied),
            );
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "absolute deadline is mandatory"
            );
            drop(sender);
        }
    }

    #[test]
    fn invalid_deadlines_deny_before_consuming_socket_data() {
        let (uid, gid) = expected_test_ids();
        let (sender, receiver) = UnixStream::pair().expect("kernel stream");
        let before = Instant::now();
        for budget in [Duration::ZERO, Duration::from_secs(6)] {
            assert_eq!(
                inspect_one_session(&receiver, uid, gid, budget),
                Err(IdentityDenied),
            );
        }
        assert!(before.elapsed() < Duration::from_secs(1));
        drop(sender);
    }

    #[test]
    fn valid_peer_with_noncanonical_or_concatenated_frame_is_denied() {
        let (uid, gid) = expected_test_ids();
        let mut invalid = valid_request();
        invalid.extend_from_slice(b"x");
        for wire in [vec![0, 0, 0, 2, b'[', b']'], invalid] {
            let (mut sender, receiver) = UnixStream::pair().expect("kernel stream");
            sender.write_all(&wire).unwrap();
            sender.shutdown(Shutdown::Write).unwrap();
            assert_eq!(
                inspect_one_session(&receiver, uid, gid, Duration::from_secs(1)),
                Err(IdentityDenied),
            );
        }
    }
}
