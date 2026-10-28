//! Non-authorizing Linux kernel descriptor inspection for a future systemd
//! socket-activated broker. Environment variables and paths alone are NOT
//! proof that a descriptor came from systemd or remains under OS custody.
use crate::activation_contract::{
    validate_absolute_socket_path, validate_activation_descriptor_set, validate_listener_shape,
};
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
    validate_absolute_socket_path(expected)?;
    if expected.len() >= size_of::<libc::sockaddr_un>() - offset_of!(libc::sockaddr_un, sun_path) {
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

/// Verify that the fixed socket's *filesystem namespace* is controlled by a
/// different, trusted principal and the socket node has exactly the declared
/// systemd ownership/mode. A kernel name string is not a namespace proof.
/// This does NOT independently authenticate LISTEN_PID/FDS as systemd.
fn inspect_custodied_named_listener(
    fd: BorrowedFd<'_>,
    expected_path: &Path,
    expected_socket_uid: libc::uid_t,
    expected_socket_gid: libc::gid_t,
    protected_dir_uid: libc::uid_t,
) -> Result<(), IdentityDenied> {
    use std::{
        ffi::CString,
        os::fd::{FromRawFd, OwnedFd},
        path::Component,
    };

    inspect_named_listener(fd, expected_path)?;
    let source = expected_path.as_os_str().as_bytes();
    if !source.starts_with(b"/") || source.ends_with(b"/") || source.windows(2).any(|w| w == b"//")
    {
        return Err(IdentityDenied);
    }
    let mut pieces = Vec::new();
    for component in expected_path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                let name = part.as_bytes();
                if name.is_empty() || name.len() > 255 {
                    return Err(IdentityDenied);
                }
                pieces.push(CString::new(name).map_err(|_| IdentityDenied)?);
            }
            _ => return Err(IdentityDenied),
        }
    }
    if pieces.len() < 2 || pieces.len() > 64 || expected_socket_uid == 0 || expected_socket_gid == 0
    {
        return Err(IdentityDenied);
    }
    let raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let mut directory = unsafe { OwnedFd::from_raw_fd(raw) };
    for (index, name) in pieces[..pieces.len() - 1].iter().enumerate() {
        let mut current = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(directory.as_raw_fd(), current.as_mut_ptr()) } != 0 {
            return Err(IdentityDenied);
        }
        let current = unsafe { current.assume_init() };
        if (current.st_mode & libc::S_IFMT) != libc::S_IFDIR
            || current.st_mode & 0o022 != 0
            || (current.st_uid != 0 && current.st_uid != protected_dir_uid)
        {
            return Err(IdentityDenied);
        }
        let next = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err(IdentityDenied);
        }
        let opened = unsafe { OwnedFd::from_raw_fd(next) };
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(opened.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
            return Err(IdentityDenied);
        }
        let metadata = unsafe { metadata.assume_init() };
        let final_parent = index + 1 == pieces.len() - 1;
        if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
            || (metadata.st_uid != 0 && metadata.st_uid != protected_dir_uid)
            || metadata.st_mode & 0o022 != 0
            || (final_parent
                && (metadata.st_uid != protected_dir_uid || metadata.st_mode & 0o7777 != 0o755))
        {
            return Err(IdentityDenied);
        }
        directory = opened;
    }
    let mut socket = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            pieces.last().ok_or(IdentityDenied)?.as_ptr(),
            socket.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(IdentityDenied);
    }
    let socket = unsafe { socket.assume_init() };
    if socket.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || socket.st_uid != expected_socket_uid
        || socket.st_gid != expected_socket_gid
        || socket.st_mode & 0o7777 != 0o660
        || socket.st_nlink != 1
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

/// Production-only acceptance: the entire socket namespace must be rooted
/// under a root-owned 0755 parent, with declared service/client UID/GID.
pub(crate) fn inspect_root_custodied_named_listener(
    fd: BorrowedFd<'_>,
    expected_path: &Path,
    expected_socket_uid: libc::uid_t,
    expected_socket_gid: libc::gid_t,
) -> Result<(), IdentityDenied> {
    inspect_custodied_named_listener(
        fd,
        expected_path,
        expected_socket_uid,
        expected_socket_gid,
        0,
    )
}

/// Convert one already-owned kernel listening FD to a long-lived Rust
/// listener, only after checking its exact path, protected directory chain,
/// socket owner/group/mode and correct AF_UNIX stream/listener shape.
/// The parent UID override is strictly internal for Linux test fixtures.
fn retain_owned_listener(
    fd: std::os::fd::OwnedFd,
    path: &Path,
    expected_uid: libc::uid_t,
    expected_gid: libc::gid_t,
    protected_parent_uid: libc::uid_t,
) -> Result<std::os::unix::net::UnixListener, IdentityDenied> {
    use std::os::fd::AsFd;
    inspect_custodied_named_listener(
        fd.as_fd(),
        path,
        expected_uid,
        expected_gid,
        protected_parent_uid,
    )?;
    let listener = std::os::unix::net::UnixListener::from(fd);
    // systemd activation FDs need not be configured nonblocking by default.
    // The bounded acceptor *requires* nonblocking mode before each poll.
    listener.set_nonblocking(true).map_err(|_| IdentityDenied)?;
    inspect_custodied_named_listener(
        listener.as_fd(),
        path,
        expected_uid,
        expected_gid,
        protected_parent_uid,
    )?;
    Ok(listener)
}

/// Single-threaded service bootstrap: adopt the one correctly named FD3
/// from the established sd-notify implementation, retain its ownership and
/// validate the independently root-managed socket namespace. LISTEN_* env
/// values alone NEVER count as privileged provenance.
pub(crate) fn retain_inherited_systemd_listener(
    expected_path: &Path,
    service_uid: libc::uid_t,
    client_gid: libc::gid_t,
) -> Result<std::os::unix::net::UnixListener, IdentityDenied> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut received = sd_notify::listen_fds_with_names().map_err(|_| IdentityDenied)?;
    let count = received.len();
    let (fd, name) = received.next().ok_or(IdentityDenied)?;
    validate_activation_descriptor_set(count, fd, &name)?;
    // SAFETY: sd-notify validated the activation inventory and returns a
    // unique FD3 to be adopted exactly once. No later borrow_raw(3) or second
    // sd-notify inventory lookup is performed in this issuer instance.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    retain_owned_listener(owned, expected_path, service_uid, client_gid, 0)
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
    fn socket_file_and_ancestor_custody_is_stricter_than_kernel_name() {
        use std::os::unix::fs::PermissionsExt;
        let home = std::env::var_os("HOME").expect("Linux CI requires HOME");
        let fixture = tempfile::tempdir_in(home).unwrap();
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = fixture.path().join("authority.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert_ne!(uid, 0, "positive control needs unprivileged Linux user");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert_eq!(inspect_named_listener(listener.as_fd(), &path), Ok(()));
        assert_eq!(
            inspect_custodied_named_listener(listener.as_fd(), &path, uid, gid, uid),
            Ok(()),
            "genuine private endpoint must be admissible in test-owned fixture"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(inspect_named_listener(listener.as_fd(), &path), Ok(()));
        assert_eq!(
            inspect_custodied_named_listener(listener.as_fd(), &path, uid, gid, uid),
            Err(IdentityDenied),
            "socket that admits arbitrary users must deny"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();

        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            inspect_custodied_named_listener(listener.as_fd(), &path, uid, gid, uid),
            Err(IdentityDenied),
            "untrusted parent can replace the socket"
        );
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            inspect_custodied_named_listener(
                listener.as_fd(),
                &path,
                uid,
                gid.wrapping_add(1),
                uid
            ),
            Err(IdentityDenied),
            "systemd SocketGroup cannot silently drift"
        );
        let saved = fixture.path().join("original.sock");
        std::fs::rename(&path, &saved).unwrap();
        std::os::unix::fs::symlink(&saved, &path).unwrap();
        assert_eq!(
            inspect_custodied_named_listener(listener.as_fd(), &path, uid, gid, uid),
            Err(IdentityDenied),
            "nofollow must reject a symlink socket name"
        );
    }

    #[test]
    fn kernel_owned_listener_is_retained_and_untrusted_fd_is_denied() {
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::os::unix::fs::PermissionsExt;
        let home = std::env::var_os("HOME").expect("Linux CI requires HOME");
        let temp = tempfile::tempdir_in(home).unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = temp.path().join("authority.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert_ne!(uid, 0);
        let owned: OwnedFd = listener.into();
        let held = retain_owned_listener(owned, &path, uid, gid, uid).unwrap();
        let flags = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0 && flags & libc::O_NONBLOCK != 0);
        let _client = UnixStream::connect(&path).unwrap();
        assert!(
            held.accept().is_ok(),
            "retained FD must still accept its real socket"
        );
        let other_path = temp.path().join("other.sock");
        let other = UnixListener::bind(&other_path).unwrap();
        let untrusted: OwnedFd = other.into();
        assert!(
            retain_owned_listener(untrusted, &path, uid, gid, uid).is_err(),
            "another listening kernel FD cannot replace the observed named endpoint"
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
