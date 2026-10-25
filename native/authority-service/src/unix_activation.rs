//! Non-authorizing Linux kernel descriptor inspection for a future systemd
//! socket-activated broker. Environment variables and paths alone are NOT
//! proof that a descriptor came from systemd or remains under OS custody.
use crate::activation_contract::{validate_activation_descriptor_set, validate_listener_shape};
use crate::IdentityDenied;
use std::mem::{offset_of, size_of, MaybeUninit};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Inspect an already borrowed descriptor; this function never takes ownership,
/// binds a socket, accepts a request, or grants a filesystem capability.
/// A separate protected manager must attest the endpoint and its identity.
pub fn inspect_named_listener(
    fd: BorrowedFd<'_>,
    expected_path: &Path,
) -> Result<(), IdentityDenied> {
    let expected = expected_path.as_os_str().as_bytes();
    // An exact absolute named socket, not an abstract or relative namespace.
    if !expected.starts_with(b"/")
        || expected.contains(&0)
        || expected.len()
            >= size_of::<libc::sockaddr_un>() - offset_of!(libc::sockaddr_un, sun_path)
    {
        return Err(IdentityDenied);
    }

    fn kernel_option(fd: BorrowedFd<'_>, option: i32) -> Result<i32, IdentityDenied> {
        let mut value = 0i32;
        let mut length = libc::socklen_t::try_from(size_of::<i32>()).map_err(|_| IdentityDenied)?;
        // SAFETY: getsockopt only writes an initialized integer into value;
        // the borrowed descriptor remains owned by the caller.
        let status = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw mut value).cast(),
                &mut length,
            )
        };
        if status != 0 || length as usize != size_of::<i32>() {
            return Err(IdentityDenied);
        }
        Ok(value)
    }

    let domain = kernel_option(fd, libc::SO_DOMAIN)?;
    let kind = kernel_option(fd, libc::SO_TYPE)?;
    let accepting = kernel_option(fd, libc::SO_ACCEPTCONN)?;
    let mut address = MaybeUninit::<libc::sockaddr_un>::zeroed();
    let mut length =
        libc::socklen_t::try_from(size_of::<libc::sockaddr_un>()).map_err(|_| IdentityDenied)?;
    // SAFETY: addr points to a correctly sized initialized sockaddr_un
    // buffer, and the kernel receives its exact capacity.
    let rc = unsafe { libc::getsockname(fd.as_raw_fd(), address.as_mut_ptr().cast(), &mut length) };
    if rc != 0
        || length as usize > size_of::<libc::sockaddr_un>()
        || (length as usize) < offset_of!(libc::sockaddr_un, sun_path) + 2
    {
        return Err(IdentityDenied);
    }
    // SAFETY: zeroed storage has an initialized representation; getsockname
    // populated the first length bytes. Read ONLY that reported prefix.
    let address = unsafe { address.assume_init() };
    if address.sun_family != libc::AF_UNIX as libc::sa_family_t {
        return Err(IdentityDenied);
    }
    let available = length as usize - offset_of!(libc::sockaddr_un, sun_path);
    let actual: Vec<u8> = address.sun_path[..available]
        .iter()
        .map(|&b| b as u8)
        .collect();
    let named = actual.first().is_some_and(|b| *b == b'/');
    // Requiring the NUL terminator disallows abstract addresses and
    // truncated or unterminated filesystem socket names.
    let terminator = actual.iter().position(|b| *b == 0);
    let matches = terminator.is_some_and(|n| actual[..n] == *expected);
    validate_listener_shape(domain, kind, accepting, named, matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};

    #[test]
    fn kernel_accepts_only_expected_listening_named_unix_stream() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owned.sock");
        let listener = UnixListener::bind(&path).unwrap();
        assert_eq!(inspect_named_listener(listener.as_fd(), &path), Ok(()));
        assert_eq!(
            inspect_named_listener(listener.as_fd(), &dir.path().join("other.sock")),
            Err(IdentityDenied)
        );
        assert_eq!(
            inspect_named_listener(listener.as_fd(), Path::new("owned.sock")),
            Err(IdentityDenied)
        );
        assert_eq!(
            inspect_named_listener(listener.as_fd(), Path::new("/not-the-owned.sock")),
            Err(IdentityDenied)
        );
    }

    #[test]
    fn kernel_rejects_connected_socket_and_datagram_descriptors() {
        let (_client, connected) = UnixStream::pair().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owned.sock");
        assert_eq!(
            inspect_named_listener(connected.as_fd(), &path),
            Err(IdentityDenied)
        );
        let datagram = UnixDatagram::bind(&path).unwrap();
        assert_eq!(
            inspect_named_listener(datagram.as_fd(), &path),
            Err(IdentityDenied)
        );
    }
}

/// Examine systemd-compatible startup descriptors using the established
/// `sd-notify` crate, then verify their kernel shape. This is an observation
/// only: LISTEN_PID/FDS/FDNAMES can be forged by the launching process and
/// cannot authenticate systemd or authorize filesystem operations.
/// Call once during single-threaded service bootstrap, before other threads
/// could close or repurpose inherited file descriptors.
pub fn inspect_inherited_systemd_listener(expected_path: &Path) -> Result<(), IdentityDenied> {
    let mut received = sd_notify::listen_fds_with_names().map_err(|_| IdentityDenied)?;
    let count = received.len();
    let (number, name) = received.next().ok_or(IdentityDenied)?;
    validate_activation_descriptor_set(count, number, &name)?;
    // SAFETY: the standard systemd activation parser checks descriptor 3 and
    // sets close-on-exec; this single-threaded observer borrows it only for
    // kernel socket inspection and never closes it or transfers ownership.
    let borrowed = unsafe { BorrowedFd::borrow_raw(number) };
    inspect_named_listener(borrowed, expected_path)
}
