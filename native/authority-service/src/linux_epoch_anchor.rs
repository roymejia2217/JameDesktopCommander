//! Read-only Linux witness owned by an independent root administrator.
//! NON-RELEASE: no publisher/updater, service installation, IPC grant or rollback recovery.
use crate::{epoch_anchor_wire::parse_epoch_digest_wire, verify_service_identity, IdentityDenied};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const DIRECTORY_FLAGS: libc::c_int =
    libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
const FILE_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// A root-owned witness is NOT authorization of a filesystem request.
/// A pathname-based SQLite matcher is not an externally usable broker API:
/// ```compile_fail
/// use jdc_authority_service::linux_epoch_anchor::verify_existing_policy_against_root_anchor;
/// let _unsafe_path_reader = verify_existing_policy_against_root_anchor;
/// ```
pub struct ObservedEpochFloor {
    epoch: u64,
    digest: [u8; 32],
}
impl ObservedEpochFloor {
    pub fn matches_snapshot(&self, epoch: u64, digest: &[u8; 32]) -> bool {
        self.epoch == epoch && self.digest == *digest
    }
}

fn metadata(fd: &impl AsRawFd) -> Result<libc::stat, IdentityDenied> {
    let mut output = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), output.as_mut_ptr()) } != 0 {
        return Err(IdentityDenied);
    }
    Ok(unsafe { output.assume_init() })
}

fn trusted_parent(st: &libc::stat) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFDIR && st.st_uid == 0 && (st.st_mode & 0o022) == 0
}
fn trusted_file(st: &libc::stat, expected_group: libc::gid_t) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFREG
        && st.st_uid == 0
        && expected_group != 0
        && st.st_gid == expected_group
        && (st.st_mode & 0o7777) == 0o640
        && st.st_nlink == 1
        && st.st_size == 40
}
fn trusted_policy_file(st: &libc::stat, expected_group: libc::gid_t) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFREG
        && st.st_uid == 0
        && expected_group != 0
        && st.st_gid == expected_group
        && (st.st_mode & 0o7777) == 0o640
        && st.st_nlink == 1
        && (512..=4 * 1024 * 1024).contains(&st.st_size)
}
fn open_component(parent: &OwnedFd, name: &std::ffi::CStr) -> Result<OwnedFd, IdentityDenied> {
    let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), DIRECTORY_FLAGS) };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    if !trusted_parent(&metadata(&owned)?) {
        return Err(IdentityDenied);
    }
    Ok(owned)
}

// Open exactly the root-owned admin directory via anchored O_PATH/O_NOFOLLOW
// kernel descriptors. The service never accepts a caller-supplied pathname.
fn open_fixed_admin_directory() -> Result<OwnedFd, IdentityDenied> {
    verify_service_identity()?;
    let raw = unsafe { libc::open(c"/".as_ptr(), DIRECTORY_FLAGS) };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let root = unsafe { OwnedFd::from_raw_fd(raw) };
    if !trusted_parent(&metadata(&root)?) {
        return Err(IdentityDenied);
    }
    let etc = open_component(&root, c"etc")?;
    let directory = open_component(&etc, c"jdc-authority")?;
    require_no_publication_intent(&directory)?;
    Ok(directory)
}

// Any administrator-owned publication intent (including an invalid marker
// or symlink) means durable state MAY be between policy and witness commits.
// Fail closed, even if the two old files currently happen to match. Only the
// independently authorized updater may establish or clear this marker.
fn require_no_publication_intent(directory: &OwnedFd) -> Result<(), IdentityDenied> {
    let mut st = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            c".policy-publish-inflight".as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err(IdentityDenied);
    }
    Ok(())
}

// A hot journal or WAL sidecar means the standalone main SQLite bytes
// cannot be proved committed without running the disk VFS/recovery.
// Refuse even symlinks and malformed entries. This uses a rooted FD,
// immutable fixed names, and does NOT follow a client-controlled pathname.
fn require_no_sqlite_sidecars(directory: &OwnedFd) -> Result<(), IdentityDenied> {
    for name in [
        c"policy.sqlite3-journal",
        c"policy.sqlite3-wal",
        c"policy.sqlite3-shm",
    ] {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
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

// The identity of an open FD is immutable, but the name it was opened
// through can be replaced after opening. Re-check the fixed leaf without
// following symlinks against the same OS-pinned parent directory descriptor.
// No caller path is accepted and no new policy file is opened.
fn require_pinned_policy_name(directory: &OwnedFd, pinned: &File) -> Result<(), IdentityDenied> {
    let handle = metadata(pinned)?;
    let mut slot = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            c"policy.sqlite3".as_ptr(),
            slot.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(IdentityDenied);
    }
    let named = unsafe { slot.assume_init() };
    if (named.st_mode & libc::S_IFMT) != libc::S_IFREG
        || named.st_nlink != 1
        || named.st_dev != handle.st_dev
        || named.st_ino != handle.st_ino
        || named.st_size != handle.st_size
        || named.st_uid != handle.st_uid
        || named.st_gid != handle.st_gid
        || (named.st_mode & 0o7777) != (handle.st_mode & 0o7777)
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

/// Read-only, root-admin-owned SQLite-file *candidate* pinned to a kernel
/// opened file object. This checks inode custody and SQLite file signature
/// only; it deliberately does NOT parse policy, attest an updater, open a
/// SQLite VFS connection, authorize a request or grant an OS capability.
pub struct ObservedAdminPolicyFile {
    directory: OwnedFd,
    file: File,
    device: u64,
    inode: u64,
}
impl ObservedAdminPolicyFile {
    pub fn file_identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    /// Consume the same verified kernel-opened file, never its original path.
    /// Serialized read-only SQLite parsing is standard rusqlite and never
    /// reopens a main database or sidecar via the process namespace.
    /// The result is DATA ONLY: caller MUST independently verify the
    /// administrator-owned monotonic witness and approved policy semantics.
    pub fn read_verified_snapshot(
        mut self,
    ) -> Result<jdc_authority_store::policy_bytes::VerifiedPolicy, IdentityDenied> {
        const MAX_IMAGE: usize = 4 * 1024 * 1024;
        require_no_publication_intent(&self.directory)?;
        require_no_sqlite_sidecars(&self.directory)?;
        require_pinned_policy_name(&self.directory, &self.file)?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| IdentityDenied)?;
        let mut bytes = Vec::new();
        (&mut self.file)
            .take((MAX_IMAGE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| IdentityDenied)?;
        let after = metadata(&self.file)?;
        if !trusted_policy_file(&after, unsafe { libc::getegid() })
            || self.device != after.st_dev
            || self.inode != after.st_ino
            || bytes.len() != after.st_size as usize
        {
            return Err(IdentityDenied);
        }
        require_no_publication_intent(&self.directory)?;
        require_no_sqlite_sidecars(&self.directory)?;
        require_pinned_policy_name(&self.directory, &self.file)?;
        let policy =
            jdc_authority_store::policy_bytes::PolicyBytesStore::read_verified_serialized(&bytes)
                .map_err(|_| IdentityDenied)?;
        // Parsing also consumes time. Deny if root published a new name
        // while the in-memory SQLite image was being validated.
        require_pinned_policy_name(&self.directory, &self.file)?;
        require_no_sqlite_sidecars(&self.directory)?;
        require_no_publication_intent(&self.directory)?;
        Ok(policy)
    }
}
/// Refuse any preexisting candidate that a less-privileged service can
/// replace, chmod, hardlink or reach through a symlink. No implicit creation.
pub fn observe_fixed_policy_database() -> Result<ObservedAdminPolicyFile, IdentityDenied> {
    let directory = open_fixed_admin_directory()?;
    require_no_sqlite_sidecars(&directory)?;
    let expected_group = unsafe { libc::getegid() };
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"policy.sqlite3".as_ptr(),
            FILE_FLAGS,
        )
    };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let before = metadata(&owned)?;
    if !trusted_policy_file(&before, expected_group) {
        return Err(IdentityDenied);
    }
    // Standard SQLite 16-byte header marker, not a proof of schema,
    // publisher authorization or tamper-resistant storage.
    let mut file = File::from(owned);
    let mut signature = [0u8; 16];
    file.read_exact(&mut signature)
        .map_err(|_| IdentityDenied)?;
    if signature != *b"SQLite format 3\0" {
        return Err(IdentityDenied);
    }
    let after = metadata(&file)?;
    if !trusted_policy_file(&after, expected_group)
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
    {
        return Err(IdentityDenied);
    }
    require_no_sqlite_sidecars(&directory)?;
    require_pinned_policy_name(&directory, &file)?;
    require_no_publication_intent(&directory)?;
    Ok(ObservedAdminPolicyFile {
        directory,
        file,
        device: after.st_dev,
        inode: after.st_ino,
    })
}

/// Independently observe the root-owned witness before and after consuming
/// the actual bounded bytes from an OS-pinned policy SQLite file. All
/// comparisons use the *effective actual policy bytes* SHA-256, not the
/// witness or a client-provided digest as the source of truth.
/// NOT an issuer: trusted updater lifecycle, semantic policy authorization,
/// replay ledger, root binding, and sidecar/publisher provenance are absent.
pub fn observe_matching_admin_policy_snapshot(
) -> Result<jdc_authority_store::policy_bytes::VerifiedPolicy, IdentityDenied> {
    let before = observe_fixed_epoch_floor()?;
    let candidate = observe_fixed_policy_database()?;
    let policy = candidate.read_verified_snapshot()?;
    let after = observe_fixed_epoch_floor()?;
    let final_authority = open_fixed_admin_directory()?;
    require_no_publication_intent(&final_authority)?;
    if !before.matches_snapshot(policy.epoch(), policy.digest())
        || !after.matches_snapshot(policy.epoch(), policy.digest())
    {
        return Err(IdentityDenied);
    }
    Ok(policy)
}

/// Fixed /etc/jdc-authority/policy-anchor. The dedicated service can READ
/// root:service 0640, but cannot create, replace, rename or chmod it.
/// No path or expected witness can be provided by the MCP client.
/// The updater must use independently administered atomic replacement.
pub fn observe_fixed_epoch_floor() -> Result<ObservedEpochFloor, IdentityDenied> {
    let authority = open_fixed_admin_directory()?;
    let group = unsafe { libc::getegid() };
    let raw = unsafe { libc::openat(authority.as_raw_fd(), c"policy-anchor".as_ptr(), FILE_FLAGS) };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    if !trusted_file(&metadata(&owned)?, group) {
        return Err(IdentityDenied);
    }
    let mut file = File::from(owned);
    let mut bytes = [0u8; 40];
    file.read_exact(&mut bytes).map_err(|_| IdentityDenied)?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra).map_err(|_| IdentityDenied)? != 0 {
        return Err(IdentityDenied);
    }
    if !trusted_file(&metadata(&file)?, group) {
        return Err(IdentityDenied);
    }
    require_no_publication_intent(&authority)?;
    let (epoch, digest) = parse_epoch_digest_wire(&bytes)?;
    Ok(ObservedEpochFloor { epoch, digest })
}

/// Offline equality proof only: SQLite is STILL opened by a pathname and
/// cannot confer authority. The witness must be opened independently first.
/// Compile into Rust unit tests only: no external pathname-based verifier.
#[cfg(test)]
pub(crate) fn verify_existing_policy_against_root_anchor(
    database: &std::path::Path,
) -> Result<jdc_authority_store::policy_bytes::VerifiedPolicy, IdentityDenied> {
    let floor = observe_fixed_epoch_floor()?;
    let store = jdc_authority_store::policy_bytes::PolicyBytesStore::open_existing(database)
        .map_err(|_| IdentityDenied)?;
    let record = store.read_verified().map_err(|_| IdentityDenied)?;
    if !floor.matches_snapshot(record.epoch(), record.digest()) {
        return Err(IdentityDenied);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_linux_directory_publication_barrier_denies_files_and_symlinks() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let directory: OwnedFd = File::open(temp.path()).unwrap().into();
        let marker = temp.path().join(".policy-publish-inflight");
        assert_eq!(require_no_publication_intent(&directory), Ok(()));
        fs::write(&marker, b"publication started").unwrap();
        assert_eq!(
            require_no_publication_intent(&directory),
            Err(IdentityDenied)
        );
        fs::remove_file(&marker).unwrap();
        assert_eq!(require_no_publication_intent(&directory), Ok(()));
        std::os::unix::fs::symlink("/does/not/exist", &marker).unwrap();
        assert_eq!(
            require_no_publication_intent(&directory),
            Err(IdentityDenied)
        );
        fs::remove_file(&marker).unwrap();
        assert_eq!(require_no_publication_intent(&directory), Ok(()));
    }

    #[test]
    fn pinned_policy_file_denies_final_name_replacement_after_fd_acquisition() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("policy.sqlite3");
        let replacement = temp.path().join("replacement.sqlite3");
        fs::write(&path, b"old policy content").unwrap();
        fs::write(&replacement, b"new policy content").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            fs::metadata(&replacement).unwrap().len(),
            "replacement must keep size constant to prove real inode identity checking"
        );
        let directory: OwnedFd = File::open(temp.path()).unwrap().into();
        let pinned = File::open(&path).unwrap();
        assert!(require_pinned_policy_name(&directory, &pinned).is_ok());
        let alias = temp.path().join("policy-hardlink.sqlite3");
        fs::hard_link(&path, &alias).unwrap();
        assert!(
            require_pinned_policy_name(&directory, &pinned).is_err(),
            "additional same-inode hardlink is not an exclusive policy object"
        );
        fs::remove_file(&alias).unwrap();
        assert!(require_pinned_policy_name(&directory, &pinned).is_ok());
        fs::rename(&replacement, &path).unwrap();
        assert!(
            require_pinned_policy_name(&directory, &pinned).is_err(),
            "same-size file renamed over the fixed name must never pass"
        );
        fs::remove_file(&path).unwrap();
        assert!(
            require_pinned_policy_name(&directory, &pinned).is_err(),
            "removed final name must not validate a stale handle"
        );
        fs::write(&replacement, b"another valid policy file").unwrap();
        std::os::unix::fs::symlink(&replacement, &path).unwrap();
        assert!(
            require_pinned_policy_name(&directory, &pinned).is_err(),
            "symlink must not redirect a previously validated handle"
        );
    }

    #[test]
    fn root_owned_sqlite_candidate_file_rejects_aliases_and_wrong_principals() {
        let file = tempfile::tempfile().unwrap();
        let mut st = metadata(&file).unwrap();
        st.st_mode = libc::S_IFREG | 0o640;
        st.st_uid = 0;
        st.st_gid = 1234;
        st.st_nlink = 1;
        st.st_size = 4096;
        assert!(trusted_policy_file(&st, 1234));
        st.st_uid = 1234;
        assert!(!trusted_policy_file(&st, 1234));
        st.st_uid = 0;
        st.st_mode = libc::S_IFREG | 0o660;
        assert!(!trusted_policy_file(&st, 1234));
        st.st_mode = libc::S_IFREG | 0o640;
        st.st_nlink = 2;
        assert!(!trusted_policy_file(&st, 1234));
        st.st_nlink = 1;
        st.st_size = 40;
        assert!(!trusted_policy_file(&st, 1234));
        st.st_size = 4096;
        assert!(!trusted_policy_file(&st, 0));
    }
    #[test]
    fn synthetic_metadata_contract_has_exact_admin_owner_group_and_mode() {
        let file = tempfile::tempfile().unwrap();
        let mut st = metadata(&file).unwrap();
        st.st_mode = libc::S_IFREG | 0o640;
        st.st_uid = 0;
        st.st_gid = 1234;
        st.st_nlink = 1;
        st.st_size = 40;
        assert!(trusted_file(&st, 1234));
        st.st_mode |= 0o020;
        assert!(!trusted_file(&st, 1234));
        st.st_mode = libc::S_IFREG | 0o640;
        st.st_nlink = 2;
        assert!(!trusted_file(&st, 1234));
        st.st_nlink = 1;
        st.st_uid = 1234;
        assert!(!trusted_file(&st, 1234));
        st.st_uid = 0;
        assert!(!trusted_file(&st, 0));
    }
    #[test]
    fn actual_root_descriptor_rejects_world_writable_tmp_ancestor() {
        let raw = unsafe { libc::open(c"/".as_ptr(), DIRECTORY_FLAGS) };
        assert!(raw >= 0, "positive kernel root descriptor required");
        let root = unsafe { OwnedFd::from_raw_fd(raw) };
        assert!(trusted_parent(&metadata(&root).unwrap()));
        let raw_tmp = unsafe { libc::openat(root.as_raw_fd(), c"tmp".as_ptr(), DIRECTORY_FLAGS) };
        assert!(raw_tmp >= 0, "actual /tmp directory required");
        let temp = unsafe { OwnedFd::from_raw_fd(raw_tmp) };
        let mode = metadata(&temp).unwrap().st_mode;
        assert_ne!(mode & 0o002, 0, "world-writable fixture required");
        assert!(open_component(&root, c"tmp").is_err());
    }
    #[test]
    fn ordinary_process_cannot_observe_or_authorize_the_fixed_witness() {
        assert!(observe_fixed_epoch_floor().is_err());
        assert!(
            verify_existing_policy_against_root_anchor(std::path::Path::new("missing")).is_err()
        );
    }
}
