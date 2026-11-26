//! Linux-only, non-authorizing request-writer evidence for a future broker.
//! SO_PEERCRED alone describes the original socket connector and remains valid
//! after SCM_RIGHTS delegation. SO_PASSCRED/SCM_CREDENTIALS is inspected for
//! each received fragment so a different writer cannot inherit that origin.
//! This does NOT attest a protected MCP launcher, policy, epoch, or root.
use crate::{
    peer_policy::{verify_message_writer, KernelPeer},
    IdentityDenied,
};
use std::{
    mem::{size_of, zeroed},
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::{Duration, Instant},
};

/// Must be enabled before accepting request bytes; failure denies operations.
pub fn enable_writer_credentials(socket: &UnixStream) -> Result<(), IdentityDenied> {
    let value: libc::c_int = 1;
    let code = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&value as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if code != 0 {
        return Err(IdentityDenied);
    }
    Ok(())
}

struct ReceivedDescriptors(Vec<libc::c_int>);
impl Drop for ReceivedDescriptors {
    fn drop(&mut self) {
        for &fd in &self.0 {
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

/// Single-byte request for the original fixed read proof.
pub fn receive_attested_byte(
    socket: &UnixStream,
    connector: KernelPeer,
) -> Result<u8, IdentityDenied> {
    let mut byte = [0u8; 1];
    receive_attested_fragment(socket, connector, &mut byte)?;
    Ok(byte[0])
}

// Authenticate each actual recvmsg fragment. No plain read fallback and no
// exposing a buffer until every fragment in the frame is authenticated.
fn receive_attested_fragment(
    socket: &UnixStream,
    connector: KernelPeer,
    bytes: &mut [u8],
) -> Result<usize, IdentityDenied> {
    if bytes.is_empty() {
        return Err(IdentityDenied);
    }
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // Native-word alignment is required by CMSG_FIRSTHDR/CMSG_NXTHDR.
    // This capacity is bounded; truncation is an error.
    let mut ancillary = [0usize; 128];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = size_of::<[usize; 128]>();
    let count = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if count <= 0 || count as usize > bytes.len() {
        return Err(IdentityDenied);
    }

    let mut received = ReceivedDescriptors(Vec::new());
    let mut writer = None;
    let mut invalid = message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let current = unsafe { &*header };
        let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
        let size = current.cmsg_len as usize;
        if size < minimum || size > message.msg_controllen {
            invalid = true;
            break;
        }
        let bytes = size - minimum;
        if current.cmsg_level == libc::SOL_SOCKET && current.cmsg_type == libc::SCM_CREDENTIALS {
            if writer.is_some() || bytes != size_of::<libc::ucred>() {
                invalid = true;
            } else {
                let observed = unsafe {
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>())
                };
                writer = Some(KernelPeer {
                    pid: observed.pid,
                    uid: observed.uid,
                    gid: observed.gid,
                });
            }
        // SCM_PIDFD (Linux include/linux/socket.h) is not yet exposed by
        // pinned libc 0.2.190. It installs a descriptor just like SCM_RIGHTS.
        // Neither ancillary type grants authority; both require RAII closure.
        } else if current.cmsg_level == libc::SOL_SOCKET
            && matches!(current.cmsg_type, libc::SCM_RIGHTS | 0x04)
        {
            if bytes.is_multiple_of(size_of::<libc::c_int>()) {
                for index in 0..(bytes / size_of::<libc::c_int>()) {
                    let fd = unsafe {
                        std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                        )
                    };
                    received.0.push(fd);
                }
            }
            // Even a well-formed descriptor must be closed and the request denied.
            invalid = true;
        } else {
            invalid = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if invalid {
        return Err(IdentityDenied);
    }
    verify_message_writer(connector, writer)?;
    Ok(count as usize)
}

// Absolute frame deadline: the timeout is not renewed by a slow client.
// The caller has exclusive read ownership and must close on any error.
fn receive_exact_attested(
    socket: &UnixStream,
    connector: KernelPeer,
    mut bytes: &mut [u8],
    start: Instant,
    timeout: Duration,
) -> Result<(), IdentityDenied> {
    while !bytes.is_empty() {
        let remaining = timeout
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or(IdentityDenied)?;
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|_| IdentityDenied)?;
        let count = receive_attested_fragment(socket, connector, bytes)?;
        if start.elapsed() >= timeout {
            return Err(IdentityDenied);
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}

/// Bounded 4-byte big-endian length framing, then exactly that many bytes.
/// This only observes kernel writer identity; it does not grant authority.
/// The caller must have authenticated the original issued process, enabled
/// SO_PASSCRED before inviting bytes, retained the process lifetime, and
/// discard the connection on error. A single frame may span many recvmsg
/// calls; every fragment must carry credentials matching the connector.
pub fn receive_attested_frame(
    socket: &UnixStream,
    connector: KernelPeer,
    max_payload: usize,
    timeout: Duration,
) -> Result<Vec<u8>, IdentityDenied> {
    const MAX_FRAME: usize = 1024 * 1024 + 8192;
    if max_payload == 0
        || max_payload > MAX_FRAME
        || timeout < Duration::from_millis(1)
        || timeout > Duration::from_secs(30)
        || crate::linux_peer::observe_kernel_peer(socket)? != connector
    {
        return Err(IdentityDenied);
    }
    let start = Instant::now();
    let mut header = [0u8; 4];
    receive_exact_attested(socket, connector, &mut header, start, timeout)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > max_payload {
        return Err(IdentityDenied);
    }
    let mut payload = vec![0; size];
    receive_exact_attested(socket, connector, &mut payload, start, timeout)?;
    Ok(payload)
}
