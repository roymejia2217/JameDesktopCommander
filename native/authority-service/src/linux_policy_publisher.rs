//! Linux root-admin-only durable publication *begin* primitive.
//! NON-RELEASE: no policy image write, witness update, recovery, grant,
//! bootstrap or MCP caller entry point. A successful begin leaves the durable
//! fail-closed intent on disk; there is intentionally NO finish/clear API.
use crate::IdentityDenied;
use std::{
    fs::File,
    io::{Read, Write},
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
/// After fsync of the marker and parent directory, the independently
/// trusted administrator may commit a validated forward policy generation.
/// Any error AFTER O_EXCL may leave the intent present, by design.
/// There is no automatic rollback/recovery or arbitrary clear operation.
pub fn begin_fixed_publication() -> Result<(), IdentityDenied> {
    let admin = open_admin_directory()?;

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

/// This is the root-only second phase after durable O_EXCL intent creation.
/// A validated next image must have a strictly greater epoch than the
/// existing, independently root-owned SQLite image and 40-byte witness.
/// This primitive is NOT an authenticated policy approval/issuer: the caller
/// is the separately trusted administrator and the service remains deny-only.
/// A mid-commit failure deliberately leaves the intent and/or staged files
/// for independent administrator-led recovery, not an automatic rollback.
pub fn commit_fixed_publication(next_image: &[u8]) -> Result<(), IdentityDenied> {
    require_root_identity()?;
    use jdc_authority_store::policy_bytes::PolicyBytesStore;
    let next =
        PolicyBytesStore::read_verified_serialized(next_image).map_err(|_| IdentityDenied)?;
    let dir = open_admin_directory()?;
    let original_intent = require_admin_intent(&dir)?;
    require_absent_sqlite_sidecars(&dir)?;

    let (old_image, group) = read_protected_fixed(&dir, c"policy.sqlite3", 512, 4 * 1024 * 1024)?;
    let (old_witness, group_witness) = read_protected_fixed(&dir, c"policy-anchor", 40, 40)?;
    if group != group_witness {
        return Err(IdentityDenied);
    }
    let old = PolicyBytesStore::read_verified_serialized(&old_image).map_err(|_| IdentityDenied)?;
    let (old_epoch, old_digest) = crate::epoch_anchor_wire::parse_epoch_digest_wire(&old_witness)?;
    if old_epoch != old.epoch() || &old_digest != old.digest() || next.epoch() <= old.epoch() {
        return Err(IdentityDenied);
    }

    let mut witness = [0u8; 40];
    witness[..8].copy_from_slice(&next.epoch().to_be_bytes());
    witness[8..].copy_from_slice(next.digest());

    stage_protected_file(&dir, c".policy-next.sqlite3", group, next_image)?;
    stage_protected_file(&dir, c".policy-next-anchor", group, &witness)?;
    sync_directory(&dir)?;

    // Detect a missing/replaced intent before publishing either name.
    if require_admin_intent(&dir)? != original_intent {
        return Err(IdentityDenied);
    }
    rename_fixed(&dir, c".policy-next.sqlite3", c"policy.sqlite3")?;
    sync_directory(&dir)?;
    rename_fixed(&dir, c".policy-next-anchor", c"policy-anchor")?;
    sync_directory(&dir)?;
    require_absent_sqlite_sidecars(&dir)?;

    // Validate what is actually published through the protected directory
    // before releasing the read-deny intent. Never trust only staged bytes.
    let (observed_image, observed_group) =
        read_protected_fixed(&dir, c"policy.sqlite3", 512, 4 * 1024 * 1024)?;
    let (observed_witness, witness_group) = read_protected_fixed(&dir, c"policy-anchor", 40, 40)?;
    if observed_group != group
        || witness_group != group
        || observed_witness.as_slice() != witness.as_slice()
        || observed_image.as_slice() != next_image
        || require_admin_intent(&dir)? != original_intent
    {
        return Err(IdentityDenied);
    }
    let verified =
        PolicyBytesStore::read_verified_serialized(&observed_image).map_err(|_| IdentityDenied)?;
    if verified.epoch() != next.epoch() || verified.digest() != next.digest() {
        return Err(IdentityDenied);
    }

    if unsafe { libc::unlinkat(dir.as_raw_fd(), c".policy-publish-inflight".as_ptr(), 0) } != 0 {
        return Err(IdentityDenied);
    }
    sync_directory(&dir)?;
    Ok(())
}

/// Administrator-only recovery for exactly ONE provable interrupted state:
/// the next SQLite image already occupies its final fixed name, the old
/// witness is still installed, and the validated next witness is staged.
/// Every other state remains DENIED for manual incident investigation.
/// The marker is never cleared unless a strictly forward matching
/// policy+witness generation was durably published and revalidated.
pub fn recover_after_policy_rename() -> Result<(), IdentityDenied> {
    use jdc_authority_store::policy_bytes::PolicyBytesStore;
    let dir = open_admin_directory()?;
    let intent = require_admin_intent(&dir)?;
    require_absent_sqlite_sidecars(&dir)?;
    require_absent_name(&dir, c".policy-next.sqlite3")?;
    let (published, published_group) =
        read_protected_fixed(&dir, c"policy.sqlite3", 512, 4 * 1024 * 1024)?;
    let (old_witness, old_group) = read_protected_fixed(&dir, c"policy-anchor", 40, 40)?;
    let (staged_witness, staged_group) =
        read_protected_fixed(&dir, c".policy-next-anchor", 40, 40)?;
    if published_group != old_group || published_group != staged_group {
        return Err(IdentityDenied);
    }
    let new_policy =
        PolicyBytesStore::read_verified_serialized(&published).map_err(|_| IdentityDenied)?;
    let (old_epoch, old_digest) = crate::epoch_anchor_wire::parse_epoch_digest_wire(&old_witness)?;
    let (next_epoch, next_digest) =
        crate::epoch_anchor_wire::parse_epoch_digest_wire(&staged_witness)?;
    // The old independent witness must have nonzero proof of a DIFFERENT
    // generation, and the new generation must strictly advance it.
    if old_epoch == 0
        || old_digest == [0; 32]
        || old_epoch >= new_policy.epoch()
        || next_epoch != new_policy.epoch()
        || next_digest != *new_policy.digest()
        || next_digest == old_digest
    {
        return Err(IdentityDenied);
    }
    if require_admin_intent(&dir)? != intent {
        return Err(IdentityDenied);
    }
    rename_fixed(&dir, c".policy-next-anchor", c"policy-anchor")?;
    sync_directory(&dir)?;
    require_absent_sqlite_sidecars(&dir)?;
    require_absent_name(&dir, c".policy-next-anchor")?;
    let (actual_policy, pgroup) =
        read_protected_fixed(&dir, c"policy.sqlite3", 512, 4 * 1024 * 1024)?;
    let (actual_witness, wgroup) = read_protected_fixed(&dir, c"policy-anchor", 40, 40)?;
    if pgroup != published_group
        || wgroup != published_group
        || actual_policy != published
        || actual_witness != staged_witness
        || require_admin_intent(&dir)? != intent
    {
        return Err(IdentityDenied);
    }
    // The already checked policy and exact witness are now jointly
    // published; a return without unlink means fail-closed partial state.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c".policy-publish-inflight".as_ptr(), 0) } != 0 {
        return Err(IdentityDenied);
    }
    sync_directory(&dir)?;
    Ok(())
}

fn require_absent_name(dir: &OwnedFd, name: &std::ffi::CStr) -> Result<(), IdentityDenied> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err(IdentityDenied);
    }
    Ok(())
}

fn require_root_identity() -> Result<(), IdentityDenied> {
    if unsafe {
        libc::getuid() != 0 || libc::geteuid() != 0 || libc::getgid() != 0 || libc::getegid() != 0
    } {
        return Err(IdentityDenied);
    }
    Ok(())
}

fn open_admin_directory() -> Result<OwnedFd, IdentityDenied> {
    require_root_identity()?;
    let raw = unsafe { libc::open(c"/".as_ptr(), DIR_FLAGS) };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let root = unsafe { OwnedFd::from_raw_fd(raw) };
    root_owned_directory(&root)?;
    let etc = root_owned_child(&root, c"etc")?;
    root_owned_child(&etc, c"jdc-authority")
}

fn sync_directory(dir: &OwnedFd) -> Result<(), IdentityDenied> {
    if unsafe { libc::fsync(dir.as_raw_fd()) } != 0 {
        return Err(IdentityDenied);
    }
    Ok(())
}

fn file_stat(fd: &impl AsRawFd) -> Result<libc::stat, IdentityDenied> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(IdentityDenied);
    }
    Ok(unsafe { stat.assume_init() })
}

fn require_admin_intent(dir: &OwnedFd) -> Result<(u64, u64), IdentityDenied> {
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c".policy-publish-inflight".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let s = file_stat(&fd)?;
    if (s.st_mode & libc::S_IFMT) != libc::S_IFREG
        || s.st_uid != 0
        || s.st_gid != 0
        || (s.st_mode & 0o7777) != 0o600
        || s.st_size != 0
        || s.st_nlink != 1
    {
        return Err(IdentityDenied);
    }
    Ok((s.st_dev, s.st_ino))
}

fn require_absent_sqlite_sidecars(dir: &OwnedFd) -> Result<(), IdentityDenied> {
    for name in [
        c"policy.sqlite3-journal",
        c"policy.sqlite3-wal",
        c"policy.sqlite3-shm",
    ] {
        let mut st = MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(IdentityDenied);
        }
    }
    Ok(())
}

fn read_protected_fixed(
    dir: &OwnedFd,
    name: &std::ffi::CStr,
    minimum: usize,
    maximum: usize,
) -> Result<(Vec<u8>, libc::gid_t), IdentityDenied> {
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let before = file_stat(&owned)?;
    if (before.st_mode & libc::S_IFMT) != libc::S_IFREG
        || before.st_uid != 0
        || before.st_gid == 0
        || (before.st_mode & 0o7777) != 0o640
        || before.st_nlink != 1
        || before.st_size < minimum as i64
        || before.st_size > maximum as i64
    {
        return Err(IdentityDenied);
    }
    let mut file = File::from(owned);
    let mut image = Vec::new();
    (&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut image)
        .map_err(|_| IdentityDenied)?;
    let after = file_stat(&file)?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
        || image.len() != before.st_size as usize
    {
        return Err(IdentityDenied);
    }
    Ok((image, before.st_gid))
}

fn stage_protected_file(
    dir: &OwnedFd,
    name: &std::ffi::CStr,
    group: libc::gid_t,
    content: &[u8],
) -> Result<(), IdentityDenied> {
    if group == 0 || content.is_empty() || content.len() > 4 * 1024 * 1024 {
        return Err(IdentityDenied);
    }
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut file = File::from(owned);
    // Never grant the service group read access to a partially written
    // generation, even through its known temporary filename.
    file.write_all(content).map_err(|_| IdentityDenied)?;
    file.sync_all().map_err(|_| IdentityDenied)?;
    if unsafe { libc::fchown(file.as_raw_fd(), 0, group) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), 0o640) } != 0
    {
        return Err(IdentityDenied);
    }
    file.sync_all().map_err(|_| IdentityDenied)?;
    let stat = file_stat(&file)?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
        || stat.st_uid != 0
        || stat.st_gid != group
        || (stat.st_mode & 0o7777) != 0o640
        || stat.st_nlink != 1
        || stat.st_size != content.len() as i64
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

fn rename_fixed(
    dir: &OwnedFd,
    from: &std::ffi::CStr,
    to: &std::ffi::CStr,
) -> Result<(), IdentityDenied> {
    if unsafe { libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr()) } != 0
    {
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
    fn nonroot_may_not_recover_an_administrator_publication() {
        assert_ne!(unsafe { libc::geteuid() }, 0);
        assert_eq!(recover_after_policy_rename(), Err(IdentityDenied));
    }

    #[test]
    fn unprivileged_service_cannot_commit_even_a_valid_looking_policy_image() {
        assert_ne!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            commit_fixed_publication(b"SQLite format 3\0"),
            Err(IdentityDenied)
        );
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
