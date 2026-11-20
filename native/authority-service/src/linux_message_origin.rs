//! Linux-only, non-authorizing request-writer evidence for a future broker.
//! SO_PEERCRED alone describes the original socket connector and remains valid
//! after SCM_RIGHTS delegation. SO_PASSCRED/SCM_CREDENTIALS is inspected for
//! each single-byte request so a different writer cannot inherit that origin.
//! This does NOT attest a protected MCP launcher, policy, epoch, or root.
use crate::{
    peer_policy::{verify_message_writer, KernelPeer},
    IdentityDenied,
};
use std::{
    mem::{size_of, zeroed},
    os::{fd::AsRawFd, unix::net::UnixStream},
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

/// One byte per authenticated frame. Larger/framed requests need a separately
/// reviewed per-fragment credential protocol, not a plain read_exact fallback.
pub fn receive_attested_byte(
    socket: &UnixStream,
    connector: KernelPeer,
) -> Result<u8, IdentityDenied> {
    let mut byte = 0u8;
    let mut vector = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
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
    if count != 1 {
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
        } else if current.cmsg_level == libc::SOL_SOCKET && current.cmsg_type == libc::SCM_RIGHTS {
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
    Ok(byte)
}
