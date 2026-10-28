//! Kernel-pinned, read/write **file observation** for the fixed Linux replay DB.
//! No SQLite VFS has been authenticated. This must NOT issue execution grants.
use crate::{linux_policy_root::ObservedPolicyDirectory, IdentityDenied};
use std::{
    fs::File,
    io::Read,
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::FileExt,
};

const NAME: &std::ffi::CStr = c"claims.sqlite3";
const SIDE_NAMES: [&std::ffi::CStr; 3] = [
    c"claims.sqlite3-journal",
    c"claims.sqlite3-wal",
    c"claims.sqlite3-shm",
];

pub struct ObservedReplayFile {
    directory: OwnedFd,
    file: File,
    identity: (u64, u64),
}

impl ObservedReplayFile {
    /// Opens only the systemd-provisioned /var/lib/jdc-authority state root.
    /// Caller input, environment variables and IPC frames cannot choose it.
    pub fn from_os_attested() -> Result<Self, IdentityDenied> {
        Self::from_verified_directory(crate::linux_policy_root::observe_provisioned_directory()?)
    }

    fn metadata(fd: &impl AsRawFd) -> Result<libc::stat, IdentityDenied> {
        let mut value = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd.as_raw_fd(), value.as_mut_ptr()) } != 0 {
            return Err(IdentityDenied);
        }
        Ok(unsafe { value.assume_init() })
    }
    /// No unexpected journal/WAL/SHM artifact is silently recovered or
    /// interpreted as a clean committed SQLite main-file state.
    fn no_sidecars(&self) -> Result<(), IdentityDenied> {
        for name in SIDE_NAMES {
            let mut st = MaybeUninit::<libc::stat>::uninit();
            let result = unsafe {
                libc::fstatat(
                    self.directory.as_raw_fd(),
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

    fn valid_leaf(st: &libc::stat) -> bool {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        uid != 0
            && gid != 0
            && st.st_uid == uid
            && st.st_gid == gid
            && (st.st_mode & libc::S_IFMT) == libc::S_IFREG
            && (st.st_mode & 0o7777) == 0o600
            && st.st_nlink == 1
            && (512..=16 * 1024 * 1024).contains(&st.st_size)
    }

    /// Observe the exact bounded SQLite content on the kernel-opened FD.
    /// Deserialization happens read-only in memory; no SQLite pathname,
    /// journal or attached VFS is opened. DATA ONLY, not replay freshness or
    /// a claim/write capability. This cannot attest a privileged rollback.
    pub fn read_verified_snapshot(&self, epoch: u64) -> Result<u32, IdentityDenied> {
        self.revalidate_name()?;
        let before = Self::metadata(&self.file)?;
        if !Self::valid_leaf(&before) {
            return Err(IdentityDenied);
        }
        let len = usize::try_from(before.st_size).map_err(|_| IdentityDenied)?;
        let mut bytes = vec![0u8; len];
        self.file
            .read_exact_at(&mut bytes, 0)
            .map_err(|_| IdentityDenied)?;
        let after = Self::metadata(&self.file)?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_size != after.st_size
            || before.st_mode != after.st_mode
            || before.st_mtime != after.st_mtime
            || before.st_mtime_nsec != after.st_mtime_nsec
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(IdentityDenied);
        }
        self.revalidate_name()?;
        let count =
            jdc_authority_store::replay_ledger::ReplayClaimLedger::inspect_serialized_snapshot(
                &bytes, epoch,
            )
            .map_err(|_| IdentityDenied)?;
        self.revalidate_name()?;
        let end = Self::metadata(&self.file)?;
        if after.st_mtime != end.st_mtime
            || after.st_mtime_nsec != end.st_mtime_nsec
            || after.st_ctime != end.st_ctime
            || after.st_ctime_nsec != end.st_ctime_nsec
        {
            return Err(IdentityDenied);
        }
        Ok(count)
    }

    pub fn identity(&self) -> (u64, u64) {
        self.identity
    }
    /// The pinned file and the fixed name must still refer to the same
    /// single-link regular inode with unchanged owner, mode and size.
    /// This does NOT prove that SQLite's separate VFS opens this FD.
    pub fn revalidate_name(&self) -> Result<(), IdentityDenied> {
        self.no_sidecars()?;
        let held = Self::metadata(&self.file)?;
        if !Self::valid_leaf(&held) || (held.st_dev, held.st_ino) != self.identity {
            return Err(IdentityDenied);
        }
        let mut slot = MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                NAME.as_ptr(),
                slot.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(IdentityDenied);
        }
        let named = unsafe { slot.assume_init() };
        if !Self::valid_leaf(&named)
            || named.st_dev != held.st_dev
            || named.st_ino != held.st_ino
            || named.st_size != held.st_size
            || named.st_mode != held.st_mode
        {
            return Err(IdentityDenied);
        }
        // A stable inode and size do not imply stable bytes. Check the exact
        // SQLite header on the pinned FD at each observation without moving
        // the shared file cursor or reopening the fixed pathname.
        let mut header = [0u8; 16];
        self.file
            .read_exact_at(&mut header, 0)
            .map_err(|_| IdentityDenied)?;
        if header != *b"SQLite format 3\x00" {
            return Err(IdentityDenied);
        }
        self.no_sidecars()
    }

    fn from_verified_directory(directory: ObservedPolicyDirectory) -> Result<Self, IdentityDenied> {
        let directory = directory.into_replay_state_fd();
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                NAME.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(IdentityDenied);
        }
        let file = File::from(unsafe { OwnedFd::from_raw_fd(raw) });
        let meta = Self::metadata(&file)?;
        if !Self::valid_leaf(&meta) {
            return Err(IdentityDenied);
        }
        let mut observed = Self {
            directory,
            file,
            identity: (meta.st_dev, meta.st_ino),
        };
        observed.revalidate_name()?;
        let mut header = [0u8; 16];
        observed
            .file
            .read_exact(&mut header)
            .map_err(|_| IdentityDenied)?;
        if header != *b"SQLite format 3\x00" {
            return Err(IdentityDenied);
        }
        observed.revalidate_name()?;
        Ok(observed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
        let home = std::env::var_os("HOME").expect("native Linux CI HOME");
        let parent = tempfile::tempdir_in(home).unwrap();
        let root = parent.path().join("state");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        (parent, root)
    }
    fn private(root: &std::path::Path) -> ObservedPolicyDirectory {
        crate::linux_policy_root::observe_test_state_directory(root.to_str().unwrap()).unwrap()
    }
    fn provision(root: &std::path::Path) -> std::path::PathBuf {
        let name = root.join("claims.sqlite3");
        let db = rusqlite::Connection::open(&name).unwrap();
        db.execute_batch(
            "PRAGMA application_id=0x4A44434C; PRAGMA user_version=1;
             CREATE TABLE replay_claims (epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)=16), PRIMARY KEY(epoch,request)) WITHOUT ROWID",
        )
        .unwrap();
        drop(db);
        std::fs::set_permissions(&name, std::fs::Permissions::from_mode(0o600)).unwrap();
        name
    }
    #[test]
    fn pinned_replay_image_is_validated_through_sqlite_without_path_reopen() {
        let (_temp, root) = setup();
        let path = provision(&root);
        let pinned = ObservedReplayFile::from_verified_directory(private(&root)).unwrap();
        assert_eq!(pinned.read_verified_snapshot(7), Ok(0));
        let db = rusqlite::Connection::open(&path).unwrap();
        let mut id = [0x31u8; 16];
        id[6] = 0x40;
        id[8] = 0x80;
        db.execute(
            "INSERT INTO replay_claims(epoch,request) VALUES (?1,?2)",
            rusqlite::params![7u64.to_be_bytes().as_slice(), id.as_slice()],
        )
        .unwrap();
        drop(db);
        assert_eq!(pinned.read_verified_snapshot(7), Ok(1));
        assert!(pinned.read_verified_snapshot(6).is_err());
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE injected (x TEXT)").unwrap();
        drop(db);
        assert!(pinned.read_verified_snapshot(7).is_err());
    }

    #[test]
    fn sqlite_exclusive_writer_denies_file_snapshot_until_transaction_ends() {
        let (_temp, root) = setup();
        let path = provision(&root);
        let pinned = ObservedReplayFile::from_verified_directory(private(&root)).unwrap();
        assert_eq!(pinned.read_verified_snapshot(7), Ok(0));
        // Real SQLite uses POSIX fcntl locks, not flock(2). BEGIN EXCLUSIVE
        // holds the kernel write lock with no journal sidecar or byte change.
        let writer = rusqlite::Connection::open(&path).unwrap();
        writer.execute_batch("BEGIN EXCLUSIVE").unwrap();
        assert_eq!(
            pinned.read_verified_snapshot(7),
            Err(IdentityDenied),
            "a concurrent SQLite write reservation must DENY even when the file is unchanged"
        );
        writer.execute_batch("ROLLBACK").unwrap();
        assert_eq!(pinned.read_verified_snapshot(7), Ok(0));
    }

    #[test]
    fn preexisting_private_sqlite_file_has_a_pinned_identity() {
        let (_temp, root) = setup();
        let name = provision(&root);
        let pinned = ObservedReplayFile::from_verified_directory(private(&root)).unwrap();
        assert_eq!(
            pinned.identity().1,
            std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&name).unwrap())
        );
        assert_eq!(pinned.revalidate_name(), Ok(()));
        let replacement = root.join("replacement.sqlite3");
        std::fs::copy(&name, &replacement).unwrap();
        std::fs::rename(&replacement, &name).unwrap();
        assert_eq!(pinned.revalidate_name(), Err(IdentityDenied));
    }
    #[test]
    fn database_custody_rejects_hardlinks_sidecars_and_restore() {
        let (_temp, root) = setup();
        let name = provision(&root);
        let hardlink = root.join("link.sqlite3");
        std::fs::hard_link(&name, &hardlink).unwrap();
        assert!(ObservedReplayFile::from_verified_directory(private(&root)).is_err());
        std::fs::remove_file(&hardlink).unwrap();
        let observed = ObservedReplayFile::from_verified_directory(private(&root)).unwrap();
        let sidecar = root.join("claims.sqlite3-journal");
        std::fs::write(&sidecar, b"hot journal").unwrap();
        assert_eq!(observed.revalidate_name(), Err(IdentityDenied));
        assert!(ObservedReplayFile::from_verified_directory(private(&root)).is_err());
        std::fs::remove_file(&sidecar).unwrap();
        std::os::unix::fs::symlink("/nonexistent", &sidecar).unwrap();
        assert!(ObservedReplayFile::from_verified_directory(private(&root)).is_err());
        std::fs::remove_file(&sidecar).unwrap();
        assert!(ObservedReplayFile::from_verified_directory(private(&root)).is_ok());
    }
    #[test]
    fn same_inode_same_size_sqlite_header_mutation_invalidates_observed_file() {
        use std::os::unix::fs::{FileExt, MetadataExt};
        let (_temp, root) = setup();
        let name = provision(&root);
        let pinned = ObservedReplayFile::from_verified_directory(private(&root)).unwrap();
        let before = std::fs::metadata(&name).unwrap();
        let writable = std::fs::OpenOptions::new().write(true).open(&name).unwrap();
        writable.write_all_at(b"X", 0).unwrap();
        writable.sync_all().unwrap();
        let after = std::fs::metadata(&name).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.len(), after.len());
        assert_eq!(pinned.revalidate_name(), Err(IdentityDenied));
    }

    #[test]
    fn symlink_malformed_permissions_or_replaced_leaf_always_deny() {
        let (_temp, root) = setup();
        let name = root.join("claims.sqlite3");
        std::os::unix::fs::symlink("/etc/passwd", &name).unwrap();
        assert!(ObservedReplayFile::from_verified_directory(private(&root)).is_err());
        std::fs::remove_file(&name).unwrap();
        std::fs::write(&name, b"NOT_SQLITE").unwrap();
        std::fs::set_permissions(&name, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ObservedReplayFile::from_verified_directory(private(&root)).is_err());
        std::fs::remove_file(&name).unwrap();
        let name = provision(&root);
        std::fs::set_permissions(&name, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(ObservedReplayFile::from_verified_directory(private(&root)).is_err());
        std::fs::set_permissions(&name, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ObservedReplayFile::from_verified_directory(private(&root)).is_ok());
    }
}
