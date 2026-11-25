//! Linux counterpart to the existing Windows policy-fenced native disclosure.
//! The independently provisioned authority must authenticate the issuer and
//! retain the root and peer lifetime before calling this operation. A numeric
//! peer/epoch or socket alone is not an authority or protected channel proof.
use crate::{
    confined_read::read_regular_at,
    linux_message_origin::receive_attested_byte,
    linux_peer::observe_kernel_peer,
    peer_policy::KernelPeer,
    policy_epoch::{PolicyFence, ReadTicket},
    IdentityDenied,
};
use std::{
    fs::File,
    io::{Error, ErrorKind},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    time::{Duration, Instant},
};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(30);

fn valid_timeout(timeout: Duration) -> bool {
    timeout >= Duration::from_millis(1) && timeout <= MAX_TIMEOUT
}

fn remaining_ms(start: Instant, timeout: Duration) -> Result<i32, IdentityDenied> {
    let remaining = timeout.checked_sub(start.elapsed()).ok_or(IdentityDenied)?;
    if remaining.is_zero() {
        return Err(IdentityDenied);
    }
    i32::try_from(remaining.as_nanos().div_ceil(1_000_000)).map_err(|_| IdentityDenied)
}

// Nonblocking send with one absolute deadline, regardless of partial writes.
// The poll is a kernel readiness wait, not an application retry timer.
fn send_all_before(
    socket: &UnixStream,
    mut bytes: &[u8],
    start: Instant,
    timeout: Duration,
) -> Result<(), IdentityDenied> {
    while !bytes.is_empty() {
        remaining_ms(start, timeout)?;
        let sent = unsafe {
            libc::send(
                socket.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent > 0 {
            let sent = usize::try_from(sent).map_err(|_| IdentityDenied)?;
            bytes = bytes.get(sent..).ok_or(IdentityDenied)?;
            continue;
        }
        if sent == 0 {
            return Err(IdentityDenied);
        }
        match Error::last_os_error().kind() {
            ErrorKind::Interrupted => continue,
            ErrorKind::WouldBlock => {
                let mut ready = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let count = unsafe { libc::poll(&mut ready, 1, remaining_ms(start, timeout)?) };
                if count < 0 && Error::last_os_error().kind() == ErrorKind::Interrupted {
                    continue;
                }
                if count != 1
                    || ready.revents & libc::POLLOUT == 0
                    || ready.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
                {
                    return Err(IdentityDenied);
                }
            }
            _ => return Err(IdentityDenied),
        }
    }
    Ok(())
}

fn disclose_bounded(
    socket: &UnixStream,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), IdentityDenied> {
    if bytes.len() > MAX_RESPONSE_BYTES || !valid_timeout(timeout) {
        return Err(IdentityDenied);
    }
    let mut header = [b'A', 0, 0, 0, 0];
    header[1..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
    let start = Instant::now();
    send_all_before(socket, &header, start, timeout)?;
    send_all_before(socket, bytes, start, timeout)
}

/// Consume a service-issued ticket, check the kernel connector and actual
/// writer, and stage the bounded read through the retained root. Revalidate
/// the epoch before disclosing under the lock. A stalled read can retain
/// a worker but cannot hold the revocation lock or disclose after revocation.
/// No owned file bytes leave this function.
///
/// The caller must have enabled SCM_CREDENTIALS before inviting the request,
/// established protected issuer identity, channel custody and root admission,
/// and must discard the channel on ANY error. A timed-out write may disclose
/// a prefix; it cannot revoke bytes already delivered. The request receive
/// and response send are bounded independently; a stalled underlying regular
/// filesystem read is not made cancellable by a socket deadline.
pub fn read_attested_regular_into_socket(
    policy: &PolicyFence,
    ticket: &ReadTicket,
    socket: &UnixStream,
    expected_peer: KernelPeer,
    root: &File,
    relative: &Path,
    timeout: Duration,
) -> Result<(), IdentityDenied> {
    policy
        .prepare_and_disclose_once(
            ticket,
            || {
                if !valid_timeout(timeout) || observe_kernel_peer(socket)? != expected_peer {
                    return Err(IdentityDenied);
                }
                socket
                    .set_read_timeout(Some(timeout))
                    .map_err(|_| IdentityDenied)?;
                if receive_attested_byte(socket, expected_peer)? != b'R' {
                    return Err(IdentityDenied);
                }
                read_regular_at(root, relative).map_err(|_| IdentityDenied)
            },
            |bytes| disclose_bounded(socket, &bytes, timeout),
        )
        .map_err(|_| IdentityDenied)?
}
