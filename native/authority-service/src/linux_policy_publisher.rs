//! Linux root-admin-only durable publication *begin* primitive.
//! NON-RELEASE: no policy image write, witness update, recovery, grant,
//! bootstrap or MCP caller entry point. A successful begin leaves the durable
//! fail-closed intent on disk; there is intentionally NO finish/clear API.
use crate::IdentityDenied;
use std::{
    fs::File,
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const DIR_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

fn trusted_directory_metadata(st: &libc::stat) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFDIR
        && st.st_uid == 0
        && st.st_gid == 0
        && (st.st_mode & 0o022) == 0
}

fn root_owned_directory(fd: &OwnedFd) -> Result<(), IdentityDenied> {
    let mut st = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(IdentityDenied);
    }
    let st = unsafe { st.assume_init() };
    if !trusted_directory_metadata(&st) {
        return Err(IdentityDenied);
    }
    Ok(())
}

fn root_owned_child(parent: &OwnedFd, name: &std::ffi::CStr) -> Result<OwnedFd, IdentityDenied> {
    let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), DIR_FLAGS) };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    root_owned_directory(&fd)?;
    Ok(fd)
}

/// Begin a generation update in the fixed, already-provisioned
/// root-owned administrative directory. Never accepts a pathname or
/// policy bytes from the MCP caller.
///
/// A root-owned 0600 marker is created using O_CREAT|O_EXCL|O_NOFOLLOW.
/// After fsync of the marker and parent directory, an admin may proceed
/// with a separately reviewed crash-consistent update protocol.
/// Any failure AFTER O_EXCL may leave the marker present, by design.
/// No action in this module clears, replaces or unlinks the marker.
pub fn begin_fixed_publication() -> Result<(), IdentityDenied> {
    if unsafe {
        libc::getuid() != 0 || libc::geteuid() != 0 || libc::getgid() != 0 || libc::getegid() != 0
    } {
        return Err(IdentityDenied);
    }

    let root_raw = unsafe { libc::open(c"/".as_ptr(), DIR_FLAGS) };
    if root_raw < 0 {
        return Err(IdentityDenied);
    }
    let root = unsafe { OwnedFd::from_raw_fd(root_raw) };
    root_owned_directory(&root)?;
    let etc = root_owned_child(&root, c"etc")?;
    let admin = root_owned_child(&etc, c"jdc-authority")?;

    let raw = unsafe {
        libc::openat(
            admin.as_raw_fd(),
            c".policy-publish-inflight".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        // Existing (even malformed/symlink) intent denies repeated begin,
        // including after an interrupted earlier publication.
        return Err(IdentityDenied);
    }
    let marker = unsafe { OwnedFd::from_raw_fd(raw) };
    if unsafe { libc::fchown(marker.as_raw_fd(), 0, 0) } != 0
        || unsafe { libc::fchmod(marker.as_raw_fd(), 0o600) } != 0
    {
        return Err(IdentityDenied);
    }
    let mut st = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(marker.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(IdentityDenied);
    }
    let st = unsafe { st.assume_init() };
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_uid != 0
        || st.st_gid != 0
        || (st.st_mode & 0o7777) != 0o600
        || st.st_nlink != 1
        || st.st_size != 0
    {
        return Err(IdentityDenied);
    }
    File::from(marker).sync_all().map_err(|_| IdentityDenied)?;
    if unsafe { libc::fsync(admin.as_raw_fd()) } != 0 {
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_unprivileged_runner_cannot_begin_an_admin_publication() {
        // The mandatory hosted Linux test process is NOT root.
        // Never run this test with administrator privileges.
        assert_ne!(unsafe { libc::geteuid() }, 0);
        assert_eq!(begin_fixed_publication(), Err(IdentityDenied));
    }

    #[test]
    fn untrusted_owner_and_writable_directory_are_not_administrative() {
        let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
        st.st_mode = libc::S_IFDIR | 0o755;
        st.st_uid = 0;
        st.st_gid = 0;
        assert!(trusted_directory_metadata(&st));
        st.st_uid = 1000;
        assert!(!trusted_directory_metadata(&st));
        st.st_uid = 0;
        st.st_mode = libc::S_IFDIR | 0o775;
        assert!(!trusted_directory_metadata(&st));
    }
}
