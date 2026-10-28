//! Kernel-pinned, read/write **file observation** for the fixed Linux replay DB.
//! No SQLite VFS has been authenticated. This must NOT issue execution grants.
use crate::{linux_policy_root::ObservedPolicyDirectory, IdentityDenied};
use std::{
    fs::File,
    io::Read,
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
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
        let mut file = File::from(unsafe { OwnedFd::from_raw_fd(raw) });
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
             CREATE TABLE replay_claims (epoch BLOB NOT NULL, request BLOB NOT NULL,
             PRIMARY KEY(epoch,request)) WITHOUT ROWID",
        )
        .unwrap();
        drop(db);
        std::fs::set_permissions(&name, std::fs::Permissions::from_mode(0o600)).unwrap();
        name
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
