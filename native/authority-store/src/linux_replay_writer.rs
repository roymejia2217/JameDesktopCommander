//! Dedicated Linux service-account replay writer using SQLite's standard unix VFS.
//! The sole production path is fixed and every ancestor/leaf is OS-verified.
//! This persists replay claims, but DOES NOT authorize filesystem execution:
//! separate admin-controlled monotonic antirollback and authenticated IPC remain P0.
use crate::{replay_ledger::ReplayClaimLedger, StoreDenied};
use rusqlite::{Connection, OpenFlags};
use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::FileExt},
    },
    path::{Component, Path},
};

const STATE_DIR: &str = "/var/lib/jdc-authority";
const DB_NAME: &CStr = c"claims.sqlite3";
const SIDECARS: [&CStr; 3] = [
    c"claims.sqlite3-journal",
    c"claims.sqlite3-wal",
    c"claims.sqlite3-shm",
];
const DB_MIN: libc::off_t = 512;
const DB_MAX: libc::off_t = 16 * 1024 * 1024;

/// Retains kernel-opened directory/file identities beside a real durable
/// SQLite writer. No public path, generic Connection or DB initialization.
pub struct LinuxReplayIssuerLedger {
    ledger: ReplayClaimLedger,
    directory: OwnedFd,
    file: File,
    identity: (u64, u64),
    permanently_revoked: bool,
}

fn metadata(fd: &impl AsRawFd) -> Result<libc::stat, StoreDenied> {
    let mut st = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(StoreDenied);
    }
    Ok(unsafe { st.assume_init() })
}

fn service_account() -> Result<(), StoreDenied> {
    let mut passwd = MaybeUninit::<libc::passwd>::uninit();
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    let rc = unsafe {
        libc::getpwnam_r(
            c"jdc-authority".as_ptr(),
            passwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() {
        return Err(StoreDenied);
    }
    let account = unsafe { passwd.assume_init() };
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    if uid == 0 || gid == 0 || uid != account.pw_uid || gid != account.pw_gid {
        return Err(StoreDenied);
    }
    Ok(())
}

fn open_checked_directory(path: &Path, production: bool) -> Result<OwnedFd, StoreDenied> {
    if !path.is_absolute() {
        return Err(StoreDenied);
    }
    let components: Vec<&OsStr> = path
        .components()
        .map(|c| match c {
            Component::RootDir => Ok(OsStr::new("")),
            Component::Normal(name) => Ok(name),
            _ => Err(StoreDenied),
        })
        .collect::<Result<_, _>>()?;
    if components.len() < 2 || components.len() > 64 || !components[0].is_empty() {
        return Err(StoreDenied);
    }
    let raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(StoreDenied);
    }
    let mut parent = unsafe { OwnedFd::from_raw_fd(raw) };
    for (i, name) in components.iter().enumerate().skip(1) {
        if name.is_empty() || name.as_bytes().len() > 255 {
            return Err(StoreDenied);
        }
        let st = metadata(&parent)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR
            || st.st_uid != 0 && (production || st.st_uid != unsafe { libc::geteuid() })
            || st.st_mode & 0o022 != 0
        {
            return Err(StoreDenied);
        }
        let component = CString::new(name.as_bytes()).map_err(|_| StoreDenied)?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                component.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(StoreDenied);
        }
        let next = unsafe { OwnedFd::from_raw_fd(raw) };
        let child = metadata(&next)?;
        let last = i == components.len() - 1;
        if child.st_mode & libc::S_IFMT != libc::S_IFDIR
            || (last
                && (child.st_uid != unsafe { libc::geteuid() }
                    || child.st_gid != unsafe { libc::getegid() }
                    || child.st_mode & 0o7777 != 0o700))
            || (!last
                && (child.st_uid != 0
                    && (production || child.st_uid != unsafe { libc::geteuid() })
                    || child.st_mode & 0o022 != 0))
        {
            return Err(StoreDenied);
        }
        parent = next;
    }
    Ok(parent)
}

fn valid_file(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
        && st.st_uid == unsafe { libc::geteuid() }
        && st.st_gid == unsafe { libc::getegid() }
        && st.st_mode & 0o7777 == 0o600
        && st.st_nlink == 1
        && (DB_MIN..=DB_MAX).contains(&st.st_size)
}

fn sidecars_absent(directory: &OwnedFd) -> Result<(), StoreDenied> {
    for name in SIDECARS {
        let mut st = MaybeUninit::<libc::stat>::uninit();
        let rc = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(StoreDenied);
        }
    }
    Ok(())
}

impl LinuxReplayIssuerLedger {
    /// No caller-supplied path, environment override, file creation or
    /// arbitrary SQLite connection. The systemd service UID is OS-attested.
    pub fn from_provisioned_service(epoch: u64) -> Result<Self, StoreDenied> {
        service_account()?;
        Self::open_checked(Path::new(STATE_DIR), epoch, true)
    }

    fn open_checked(state: &Path, epoch: u64, production: bool) -> Result<Self, StoreDenied> {
        if epoch == 0 {
            return Err(StoreDenied);
        }
        let directory = open_checked_directory(state, production)?;
        sidecars_absent(&directory)?;
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                DB_NAME.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(StoreDenied);
        }
        let file = File::from(unsafe { OwnedFd::from_raw_fd(raw) });
        let st = metadata(&file)?;
        if !valid_file(&st) {
            return Err(StoreDenied);
        }
        let mut header = [0u8; 16];
        file.read_exact_at(&mut header, 0)
            .map_err(|_| StoreDenied)?;
        if header != *b"SQLite format 3\0" {
            return Err(StoreDenied);
        }

        // Protected 0700 directory with all nonfinal production ancestors
        // root-owned: no different unprivileged process may rename the DB
        // or plant a SQLite journal in this namespace. The standard unix
        // VFS (not /proc/self/fd) owns SQLite journal and POSIX locking.
        let path = state.join("claims.sqlite3");
        let db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .map_err(|_| StoreDenied)?;
        let ledger = ReplayClaimLedger::from_existing_connection(db, epoch)?;
        let opened = Self {
            ledger,
            directory,
            file,
            identity: (st.st_dev, st.st_ino),
            permanently_revoked: false,
        };
        opened.revalidate()?;
        Ok(opened)
    }

    fn revalidate(&self) -> Result<(), StoreDenied> {
        sidecars_absent(&self.directory)?;
        let held = metadata(&self.file)?;
        if !valid_file(&held) || (held.st_dev, held.st_ino) != self.identity {
            return Err(StoreDenied);
        }
        let mut named = MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                DB_NAME.as_ptr(),
                named.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(StoreDenied);
        }
        let named = unsafe { named.assume_init() };
        if !valid_file(&named) || named.st_dev != held.st_dev || named.st_ino != held.st_ino {
            return Err(StoreDenied);
        }
        let mut header = [0u8; 16];
        self.file
            .read_exact_at(&mut header, 0)
            .map_err(|_| StoreDenied)?;
        if header != *b"SQLite format 3\0" {
            return Err(StoreDenied);
        }
        sidecars_absent(&self.directory)
    }

    /// Validate pinned state without issuing any filesystem operation.
    /// A prior uncertain claim cannot be reactivated by a new observation.
    pub fn validate_custody(&self) -> Result<(), StoreDenied> {
        if self.permanently_revoked {
            return Err(StoreDenied);
        }
        self.revalidate()
    }

    /// Irreversibly revoke this writer when the independent administrative
    /// witness, peer identity or policy epoch no longer matches.
    pub fn revoke(&mut self) {
        self.permanently_revoked = true;
    }

    /// Commit exactly once in the immutable constructor-bound epoch, then
    /// revalidate OS file custody. Any uncertainty permanently poisons this
    /// ledger. There is no replay caching or implicit retry.
    pub fn claim_once(&mut self, id: [u8; 16]) -> Result<(), StoreDenied> {
        if self.permanently_revoked {
            return Err(StoreDenied);
        }
        let result = self
            .revalidate()
            .and_then(|_| self.ledger.claim_once(id))
            .and_then(|_| self.revalidate());
        if result.is_err() {
            self.permanently_revoked = true;
        }
        result
    }

    #[cfg(test)]
    fn open_protected_fixture(state: &Path, epoch: u64) -> Result<Self, StoreDenied> {
        Self::open_checked(state, epoch, false)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let home = std::env::var_os("HOME").expect("Linux CI HOME");
        let temp = tempfile::tempdir_in(home).unwrap();
        let dir = temp.path().join("state");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("claims.sqlite3");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(concat!(
            "PRAGMA application_id=0x4A44434C; PRAGMA user_version=1;",
            "CREATE TABLE replay_claims (epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), ",
            "request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)=16), ",
            "PRIMARY KEY(epoch,request)) WITHOUT ROWID"
        )).unwrap();
        drop(db);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (temp, dir)
    }

    fn id() -> [u8; 16] {
        let mut id = [0x17; 16];
        id[6] = 0x40;
        id[8] = 0x80;
        id
    }

    #[test]
    fn protected_writer_persists_across_restart_and_rejects_insecure_modes() {
        let (_temp, dir) = fixture();
        let mut writer = LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).unwrap();
        writer.claim_once(id()).unwrap();
        assert!(writer.claim_once(id()).is_err());
        drop(writer);
        assert!(LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7)
            .unwrap()
            .claim_once(id())
            .is_err());
        let db = Connection::open(dir.join("claims.sqlite3")).unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM replay_claims", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
        drop(db);
        std::fs::set_permissions(
            dir.join("claims.sqlite3"),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).is_err());
        std::fs::set_permissions(
            dir.join("claims.sqlite3"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).is_err());
    }

    #[test]
    fn protected_writer_denies_swapped_db_hardlink_symlink_and_sidecar() {
        let (_temp, dir) = fixture();
        let name = dir.join("claims.sqlite3");
        let mut writer = LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).unwrap();
        let replacement = dir.join("replacement.sqlite3");
        std::fs::copy(&name, &replacement).unwrap();
        std::fs::rename(&replacement, &name).unwrap();
        assert!(
            writer.claim_once(id()).is_err(),
            "retained FD must detect leaf replacement"
        );
        drop(writer);
        let db = Connection::open(&name).unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM replay_claims", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        drop(db);
        let link = dir.join("foreign-link");
        std::fs::hard_link(&name, &link).unwrap();
        assert!(LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).is_err());
        std::fs::remove_file(&link).unwrap();
        let sidecar = dir.join("claims.sqlite3-journal");
        std::os::unix::fs::symlink("/etc/passwd", &sidecar).unwrap();
        assert!(LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).is_err());
        std::fs::remove_file(&sidecar).unwrap();
        let alias = dir.join("alias.sqlite3");
        std::fs::rename(&name, &alias).unwrap();
        std::os::unix::fs::symlink(&alias, &name).unwrap();
        assert!(LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).is_err());
    }

    #[test]
    fn custodied_writer_refuses_corrupt_historical_uuid_without_committing() {
        let (_temp, dir) = fixture();
        let path = dir.join("claims.sqlite3");
        let mut writer = LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).unwrap();
        let db = Connection::open(&path).unwrap();
        db.execute(
            "INSERT INTO replay_claims(epoch,request) VALUES (?1,?2)",
            rusqlite::params![7u64.to_be_bytes().as_slice(), [0x11u8; 16].as_slice()],
        )
        .unwrap();
        drop(db);
        assert!(writer.claim_once(id()).is_err());
        assert!(
            writer.claim_once(id()).is_err(),
            "failed writer must remain revoked"
        );
        let db = Connection::open(&path).unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM replay_claims", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn revocation_permanently_disables_the_writer_without_a_claim() {
        let (_temp, dir) = fixture();
        let mut writer = LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).unwrap();
        assert_eq!(writer.validate_custody(), Ok(()));
        writer.revoke();
        assert!(writer.validate_custody().is_err());
        assert!(writer.claim_once(id()).is_err());
        let db = Connection::open(dir.join("claims.sqlite3")).unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM replay_claims", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn unprovisioned_host_cannot_invoke_production_writer() {
        assert!(LinuxReplayIssuerLedger::from_provisioned_service(7).is_err());
    }
}
