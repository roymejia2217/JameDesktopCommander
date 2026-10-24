//! Linux-only observation of kernel-issued peer credentials for a *connected*
//! AF_UNIX stream. This is not a grant of authority, a peer allowlist, or an
//! IPC listener. No client-provided UID/PID text is parsed or trusted.
//!
//! SO_PEERCRED reflects credentials at connect/listen/socketpair time, not a
//! continuous guarantee about subsequent process privileges. A future broker
//! must separately attest the expected client identity from protected policy
//! and authenticate its socket endpoint before authorizing any operation.
use std::mem::{size_of, MaybeUninit};
use std::os::fd::{AsRawFd, BorrowedFd};

use crate::peer_contract::{validate_connected_unix_stream, validate_kernel_peer};
use crate::IdentityDenied;

/// Observed metadata only; this type is not a capability or authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelPeer {
    pid: i32,
    uid: u32,
    gid: u32,
}

impl KernelPeer {
    #[must_use]
    pub fn pid(&self) -> i32 {
        self.pid
    }

    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    #[must_use]
    pub fn gid(&self) -> u32 {
        self.gid
    }
}

fn read_socket_integer_option(fd: BorrowedFd<'_>, name: i32) -> Result<i32, IdentityDenied> {
    let mut value: i32 = 0;
    let mut len = libc::socklen_t::try_from(size_of::<i32>()).map_err(|_| IdentityDenied)?;
    // SAFETY: the kernel writes into the live, correctly sized scalar buffer.
    // Check the exact written length before accepting the result.
    let status = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            name,
            (&raw mut value).cast(),
            &mut len,
        )
    };
    if status != 0 || len as usize != size_of::<i32>() {
        return Err(IdentityDenied);
    }
    Ok(value)
}

fn require_connected_unix_stream(fd: BorrowedFd<'_>) -> Result<(), IdentityDenied> {
    let domain = read_socket_integer_option(fd, libc::SO_DOMAIN)?;
    let socket_type = read_socket_integer_option(fd, libc::SO_TYPE)?;
    let mut address = MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut length = libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>())
        .map_err(|_| IdentityDenied)?;
    // SAFETY: getpeername writes only inside the declared sockaddr_storage.
    // No address bytes are dereferenced, including after a failure.
    let connected =
        unsafe { libc::getpeername(fd.as_raw_fd(), address.as_mut_ptr().cast(), &mut length) == 0 };
    validate_connected_unix_stream(domain, socket_type, connected)?;
    if (length as usize) < size_of::<libc::sa_family_t>()
        || (length as usize) > size_of::<libc::sockaddr_storage>()
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

/// Inspect a kernel-owned *connected* Unix stream descriptor. A mismatched
/// domain/type, unconnected stream, invalid kernel result or root/unknown
/// peer is denied. BorrowedFd retains ownership with the caller.
/// This observation cannot authorize a filesystem operation.
pub fn observe_connected_peer(fd: BorrowedFd<'_>) -> Result<KernelPeer, IdentityDenied> {
    require_connected_unix_stream(fd)?;
    let mut value = MaybeUninit::<libc::ucred>::uninit();
    let mut len =
        libc::socklen_t::try_from(size_of::<libc::ucred>()).map_err(|_| IdentityDenied)?;
    // SAFETY: getsockopt writes no more than the supplied ucred-sized buffer;
    // this FD remains valid through BorrowedFd and len reports initialized
    // bytes. We never read value if the syscall fails or returns a short size.
    let status = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            value.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if status != 0 || len as usize != size_of::<libc::ucred>() {
        return Err(IdentityDenied);
    }
    // SAFETY: successful getsockopt with exact size initialized all fields.
    let kernel = unsafe { value.assume_init() };
    validate_kernel_peer(kernel.pid, kernel.uid, kernel.gid)?;
    Ok(KernelPeer {
        pid: kernel.pid,
        uid: kernel.uid,
        gid: kernel.gid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};
    use std::os::unix::net::{UnixDatagram, UnixStream};

    #[test]
    fn connected_peer_is_from_kernel_not_client_claims() {
        // The OS principal and group must be a non-root CI identity for this
        // positive control; otherwise a blanket-deny could masquerade as PASS.
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert_ne!(uid, 0, "dedicated unprivileged runner required");
        assert_ne!(gid, 0, "dedicated unprivileged group required");
        let (mut client, server) = UnixStream::pair().expect("kernel socket pair");
        client
            .write_all(b"pid=1;uid=0;gid=0;allow=true")
            .expect("untrusted forged identity payload");
        let actual =
            observe_connected_peer(server.as_fd()).expect("connected peer kernel evidence");
        assert_eq!(actual.pid(), std::process::id() as i32);
        assert_eq!(actual.uid(), uid);
        assert_eq!(actual.gid(), gid);
    }

    #[test]
    fn unix_datagram_socketpair_is_not_a_connected_stream_peer() {
        // SO_PEERCRED may return credentials for this UNIX socket even though
        // the C4g contract permits only connected byte-stream transports.
        let (_client, server) = UnixDatagram::pair().expect("kernel UNIX datagram pair");
        assert_eq!(observe_connected_peer(server.as_fd()), Err(IdentityDenied));
    }

    #[test]
    fn unconnected_unix_stream_is_not_a_peer() {
        // Test the real kernel, not merely the pure structural helper.
        // SAFETY: socket returns a new owned descriptor on success; OwnedFd
        // takes exclusive responsibility to close it exactly once.
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(raw >= 0, "unconnected UNIX socket must be constructible");
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_eq!(observe_connected_peer(fd.as_fd()), Err(IdentityDenied));
    }

    #[test]
    fn non_socket_fd_cannot_become_an_authenticated_local_peer() {
        let executable = std::env::current_exe().expect("running test executable");
        let ordinary_file = std::fs::File::open(executable).expect("own executable is readable");
        assert_eq!(
            observe_connected_peer(ordinary_file.as_fd()),
            Err(IdentityDenied)
        );
    }
}
