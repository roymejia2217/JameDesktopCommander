//! Read-only Linux witness owned by an independent root administrator.
//! NON-RELEASE: no publisher/updater, service installation, IPC grant or rollback recovery.
use crate::{epoch_anchor_wire::parse_epoch_digest_wire, verify_service_identity, IdentityDenied};
use std::{
    fs::File,
    io::Read,
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const DIRECTORY_FLAGS: libc::c_int =
    libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
const FILE_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// A root-owned witness is NOT authorization of a filesystem request.
pub struct ObservedEpochFloor {
    epoch: u64,
    digest: [u8; 32],
}
impl ObservedEpochFloor {
    pub fn matches_snapshot(&self, epoch: u64, digest: &[u8; 32]) -> bool {
        self.epoch == epoch && self.digest == *digest
    }
}

fn metadata(fd: &OwnedFd) -> Result<libc::stat, IdentityDenied> {
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

/// Fixed /etc/jdc-authority/policy-anchor. The dedicated service can READ
/// root:service 0640, but cannot create, replace, rename or chmod it.
/// No path or expected witness can be provided by the MCP client.
/// The updater must use independently administered atomic replacement.
pub fn observe_fixed_epoch_floor() -> Result<ObservedEpochFloor, IdentityDenied> {
    verify_service_identity()?;
    let group = unsafe { libc::getegid() };
    let raw = unsafe { libc::open(c"/".as_ptr(), DIRECTORY_FLAGS) };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let root = unsafe { OwnedFd::from_raw_fd(raw) };
    if !trusted_parent(&metadata(&root)?) {
        return Err(IdentityDenied);
    }
    let etc = open_component(&root, c"etc")?;
    let authority = open_component(&etc, c"jdc-authority")?;
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
    if !trusted_file(&metadata(&file.into())?, group) {
        return Err(IdentityDenied);
    }
    let (epoch, digest) = parse_epoch_digest_wire(&bytes)?;
    Ok(ObservedEpochFloor { epoch, digest })
}

/// Offline equality proof only: SQLite is STILL opened by a pathname and
/// cannot confer authority. The witness must be opened independently first.
pub fn verify_existing_policy_against_root_anchor(
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
    fn synthetic_metadata_contract_has_exact_admin_owner_group_and_mode() {
        let file = tempfile::tempfile().unwrap();
        let mut st = metadata(&file.into()).unwrap();
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
