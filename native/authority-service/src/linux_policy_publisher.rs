//! Linux root-admin-owned durable policy publication and narrow recovery.
//! NON-RELEASE: not a signed policy approval, live grant, broker bootstrap,
//! MCP operation endpoint, or complete crash/recovery/antirollback protocol.
//! A failed partial update deliberately preserves the fail-closed intent.
use crate::IdentityDenied;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
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

// Stored in the existing root:root 0600 O_EXCL publication intent.
// Must be durable BEFORE the first stage write/rename; a zero/partial
// marker still forces reader DENY and cannot be used for recovery.
const INTENT_RECORD_SIZE: usize = 88;
const INTENT_RECORD_MAGIC: [u8; 8] = *b"JDC-POL1";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PolicyTransitionRecord {
    old_epoch: u64,
    old_digest: [u8; 32],
    next_epoch: u64,
    next_digest: [u8; 32],
}
impl PolicyTransitionRecord {
    fn new(
        old_epoch: u64,
        old_digest: [u8; 32],
        next_epoch: u64,
        next_digest: [u8; 32],
    ) -> Result<Self, IdentityDenied> {
        if old_epoch == 0
            || next_epoch <= old_epoch
            || old_digest == [0; 32]
            || next_digest == [0; 32]
            || old_digest == next_digest
        {
            return Err(IdentityDenied);
        }
        Ok(Self {
            old_epoch,
            old_digest,
            next_epoch,
            next_digest,
        })
    }
    fn encode(self) -> [u8; INTENT_RECORD_SIZE] {
        let mut bytes = [0u8; INTENT_RECORD_SIZE];
        bytes[..8].copy_from_slice(&INTENT_RECORD_MAGIC);
        bytes[8..16].copy_from_slice(&self.old_epoch.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.old_digest);
        bytes[48..56].copy_from_slice(&self.next_epoch.to_be_bytes());
        bytes[56..88].copy_from_slice(&self.next_digest);
        bytes
    }
    fn decode(raw: &[u8]) -> Result<Self, IdentityDenied> {
        if raw.len() != INTENT_RECORD_SIZE || raw[..8] != INTENT_RECORD_MAGIC {
            return Err(IdentityDenied);
        }
        let mut old_digest = [0u8; 32];
        old_digest.copy_from_slice(&raw[16..48]);
        let mut next_digest = [0u8; 32];
        next_digest.copy_from_slice(&raw[56..88]);
        Self::new(
            u64::from_be_bytes(raw[8..16].try_into().map_err(|_| IdentityDenied)?),
            old_digest,
            u64::from_be_bytes(raw[48..56].try_into().map_err(|_| IdentityDenied)?),
            next_digest,
        )
    }
}

/// The root administrator can persist a *precise* forward transition without
/// exposing any new policy to the service. Only usable after an O_EXCL begin.
/// This is NOT a signed source/provenance validator or a capability issuer.
pub fn prepare_fixed_publication(next_image: &[u8]) -> Result<(), IdentityDenied> {
    use jdc_authority_store::policy_bytes::PolicyBytesStore;
    let next =
        PolicyBytesStore::read_verified_serialized(next_image).map_err(|_| IdentityDenied)?;
    let dir = open_admin_directory()?;
    let original = require_admin_intent(&dir)?;
    require_absent_sqlite_sidecars(&dir)?;
    let (old_image, group) = read_protected_fixed(&dir, c"policy.sqlite3", 512, 4 * 1024 * 1024)?;
    let (witness, witness_group) = read_protected_fixed(&dir, c"policy-anchor", 40, 40)?;
    if group != witness_group {
        return Err(IdentityDenied);
    }
    let old = PolicyBytesStore::read_verified_serialized(&old_image).map_err(|_| IdentityDenied)?;
    let (old_epoch, old_digest) = crate::epoch_anchor_wire::parse_epoch_digest_wire(&witness)?;
    if old_epoch != old.epoch() || old_digest != *old.digest() {
        return Err(IdentityDenied);
    }
    let expected =
        PolicyTransitionRecord::new(old_epoch, old_digest, next.epoch(), *next.digest())?;
    bind_transition_to_intent(&dir, original, expected)
}

fn bind_transition_to_intent(
    dir: &OwnedFd,
    original: (u64, u64),
    expected: PolicyTransitionRecord,
) -> Result<(), IdentityDenied> {
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c".policy-publish-inflight".as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(IdentityDenied);
    }
    let mut file = File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let before = file_stat(&file)?;
    if (before.st_dev, before.st_ino) != original
        || ![0, INTENT_RECORD_SIZE as i64].contains(&before.st_size)
        || before.st_uid != 0
        || before.st_gid != 0
        || (before.st_mode & libc::S_IFMT) != libc::S_IFREG
        || (before.st_mode & 0o7777) != 0o600
        || before.st_nlink != 1
    {
        return Err(IdentityDenied);
    }
    if before.st_size == 0 {
        file.write_all(&expected.encode())
            .map_err(|_| IdentityDenied)?;
        file.sync_all().map_err(|_| IdentityDenied)?;
        sync_directory(dir)?;
    } else {
        let mut old = [0u8; INTENT_RECORD_SIZE];
        file.read_exact(&mut old).map_err(|_| IdentityDenied)?;
        if PolicyTransitionRecord::decode(&old)? != expected {
            return Err(IdentityDenied);
        }
    }
    let after = file_stat(&file)?;
    if (after.st_dev, after.st_ino) != original
        || after.st_size != INTENT_RECORD_SIZE as i64
        || require_admin_intent(dir)? != original
    {
        return Err(IdentityDenied);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| IdentityDenied)?;
    let mut persisted = [0u8; INTENT_RECORD_SIZE];
    file.read_exact(&mut persisted)
        .map_err(|_| IdentityDenied)?;
    if PolicyTransitionRecord::decode(&persisted)? != expected {
        return Err(IdentityDenied);
    }
    Ok(())
}

fn read_transition_intent(
    dir: &OwnedFd,
    identity: (u64, u64),
) -> Result<PolicyTransitionRecord, IdentityDenied> {
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
    let mut file = File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let before = file_stat(&file)?;
    if (before.st_dev, before.st_ino) != identity
        || before.st_size != INTENT_RECORD_SIZE as i64
        || before.st_uid != 0
        || before.st_gid != 0
        || (before.st_mode & 0o7777) != 0o600
        || before.st_nlink != 1
    {
        return Err(IdentityDenied);
    }
    let mut bytes = [0u8; INTENT_RECORD_SIZE];
    file.read_exact(&mut bytes).map_err(|_| IdentityDenied)?;
    let after = file_stat(&file)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || require_admin_intent(dir)? != identity
    {
        return Err(IdentityDenied);
    }
    PolicyTransitionRecord::decode(&bytes)
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
    bind_transition_to_intent(
        &dir,
        original_intent,
        PolicyTransitionRecord::new(old_epoch, old_digest, next.epoch(), *next.digest())?,
    )?;

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

/// Root-only recovery for the precise state *before* either final rename:
/// old policy and witness remain installed, while two complete staged
/// files match a previously durable root-owned forward transition record.
/// No generic intent reset, grant, path argument or rollback is provided.
pub fn recover_before_policy_rename() -> Result<(), IdentityDenied> {
    use jdc_authority_store::policy_bytes::PolicyBytesStore;
    let dir = open_admin_directory()?;
    let intent = require_admin_intent(&dir)?;
    let record = read_transition_intent(&dir, intent)?;
    require_absent_sqlite_sidecars(&dir)?;

    let (old_image, old_group) =
        read_protected_fixed(&dir, c"policy.sqlite3", 512, 4 * 1024 * 1024)?;
    let (old_witness, witness_group) =
        read_protected_fixed(&dir, c"policy-anchor", 40, 40)?;
    let (next_image, next_group) =
        read_protected_fixed(&dir, c".policy-next.sqlite3", 512, 4 * 1024 * 1024)?;
    let (next_witness, next_witness_group) =
        read_protected_fixed(&dir, c".policy-next-anchor", 40, 40)?;
    if old_group != witness_group
        || old_group != next_group
        || old_group != next_witness_group
    {
        return Err(IdentityDenied);
    }

    let old = PolicyBytesStore::read_verified_serialized(&old_image)
        .map_err(|_| IdentityDenied)?;
    let next = PolicyBytesStore::read_verified_serialized(&next_image)
        .map_err(|_| IdentityDenied)?;
    let (old_epoch, old_digest) =
        crate::epoch_anchor_wire::parse_epoch_digest_wire(&old_witness)?;
    let (next_epoch, next_digest) =
        crate::epoch_anchor_wire::parse_epoch_digest_wire(&next_witness)?;
    if old.epoch() != record.old_epoch
        || *old.digest() != record.old_digest
        || old_epoch != record.old_epoch
        || old_digest != record.old_digest
        || next.epoch() != record.next_epoch
        || *next.digest() != record.next_digest
        || next_epoch != record.next_epoch
        || next_digest != record.next_digest
    {
        return Err(IdentityDenied);
    }

    // Recheck the identity and content of every fixed/staged entry before
    // switching names; a changed record or unexpected sidecar fails closed.
    for (name, original, min, max) in [
        (c"policy.sqlite3".as_ref(), old_image.as_slice(), 512, 4 * 1024 * 1024),
        (c"policy-anchor".as_ref(), old_witness.as_slice(), 40, 40),
        (c".policy-next.sqlite3".as_ref(), next_image.as_slice(), 512, 4 * 1024 * 1024),
        (c".policy-next-anchor".as_ref(), next_witness.as_slice(), 40, 40),
    ] {
        let (again, group) = read_protected_fixed(&dir, name, min, max)?;
        if again.as_slice() != original || group != old_group {
            return Err(IdentityDenied);
        }
    }
    if require_admin_intent(&dir)? != intent || read_transition_intent(&dir, intent)? != record {
        return Err(IdentityDenied);
    }
    require_absent_sqlite_sidecars(&dir)?;

    rename_fixed(&dir, c".policy-next.sqlite3", c"policy.sqlite3")?;
    sync_directory(&dir)?;
    rename_fixed(&dir, c".policy-next-anchor", c"policy-anchor")?;
    sync_directory(&dir)?;
    require_absent_sqlite_sidecars(&dir)?;
    require_absent_name(&dir, c".policy-next.sqlite3")?;
    require_absent_name(&dir, c".policy-next-anchor")?;
    let (published, pgroup) =
        read_protected_fixed(&dir, c"policy.sqlite3", 512, 4 * 1024 * 1024)?;
    let (witness, wgroup) =
        read_protected_fixed(&dir, c"policy-anchor", 40, 40)?;
    if published != next_image
        || witness != next_witness
        || pgroup != old_group
        || wgroup != old_group
        || require_admin_intent(&dir)? != intent
        || read_transition_intent(&dir, intent)? != record
    {
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
    let record = read_transition_intent(&dir, intent)?;
    // The old independent witness must have nonzero proof of a DIFFERENT
    // generation, and the new generation must strictly advance it.
    if old_epoch == 0
        || old_digest == [0; 32]
        || old_epoch >= new_policy.epoch()
        || next_epoch != new_policy.epoch()
        || next_digest != *new_policy.digest()
        || next_digest == old_digest
        || old_epoch != record.old_epoch
        || old_digest != record.old_digest
        || next_epoch != record.next_epoch
        || next_digest != record.next_digest
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

/// Root-only recovery for a fully installed, strictly forward generation
/// whose final durable marker removal was interrupted. This is NOT
/// permission to clear an arbitrary stale intent: it requires the exact
/// persisted old/new transition and both verified final objects, with no
/// staged names left. All ambiguous states remain fail-closed.
pub fn recover_after_witness_rename() -> Result<(), IdentityDenied> {
    use jdc_authority_store::policy_bytes::PolicyBytesStore;
    let dir = open_admin_directory()?;
    let intent = require_admin_intent(&dir)?;
    let record = read_transition_intent(&dir, intent)?;
    require_absent_sqlite_sidecars(&dir)?;
    require_absent_name(&dir, c".policy-next.sqlite3")?;
    require_absent_name(&dir, c".policy-next-anchor")?;

    let (actual_image, policy_group) =
        read_protected_fixed(&dir, c"policy.sqlite3", 512, 4 * 1024 * 1024)?;
    let (actual_witness, witness_group) = read_protected_fixed(&dir, c"policy-anchor", 40, 40)?;
    if policy_group != witness_group {
        return Err(IdentityDenied);
    }
    let policy =
        PolicyBytesStore::read_verified_serialized(&actual_image).map_err(|_| IdentityDenied)?;
    let (epoch, digest) = crate::epoch_anchor_wire::parse_epoch_digest_wire(&actual_witness)?;
    if epoch != record.next_epoch
        || digest != record.next_digest
        || policy.epoch() != record.next_epoch
        || *policy.digest() != record.next_digest
    {
        return Err(IdentityDenied);
    }

    // Reopen both fixed objects and confirm they remained byte-identical
    // and under the same trusted root:service principal before clearing.
    let (again_image, again_policy_group) =
        read_protected_fixed(&dir, c"policy.sqlite3", 512, 4 * 1024 * 1024)?;
    let (again_witness, again_witness_group) =
        read_protected_fixed(&dir, c"policy-anchor", 40, 40)?;
    if again_policy_group != policy_group
        || again_witness_group != witness_group
        || again_image != actual_image
        || again_witness != actual_witness
        || require_admin_intent(&dir)? != intent
        || read_transition_intent(&dir, intent)? != record
    {
        return Err(IdentityDenied);
    }
    require_absent_sqlite_sidecars(&dir)?;
    require_absent_name(&dir, c".policy-next.sqlite3")?;
    require_absent_name(&dir, c".policy-next-anchor")?;

    // Both files were already published and durably validated. Only
    // the exact original intent inode is removed; never touch policy bytes.
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
        || ![0, INTENT_RECORD_SIZE as i64].contains(&s.st_size)
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
    fn durable_transition_wire_roundtrips_and_rejects_truncation_downgrade() {
        let record = PolicyTransitionRecord::new(7, [0x11; 32], 8, [0x22; 32]).unwrap();
        assert_eq!(record.encode().len(), INTENT_RECORD_SIZE);
        assert_eq!(PolicyTransitionRecord::decode(&record.encode()), Ok(record));
        assert_eq!(
            PolicyTransitionRecord::decode(&record.encode()[..87]),
            Err(IdentityDenied)
        );
        let mut corrupted = record.encode();
        corrupted[0] = b'X';
        assert_eq!(
            PolicyTransitionRecord::decode(&corrupted),
            Err(IdentityDenied)
        );
        assert_eq!(
            PolicyTransitionRecord::new(7, [0x11; 32], 7, [0x22; 32]),
            Err(IdentityDenied)
        );
        assert_eq!(
            PolicyTransitionRecord::new(7, [0x11; 32], 8, [0x11; 32]),
            Err(IdentityDenied)
        );
    }

    #[test]
    fn unprivileged_process_cannot_clear_even_a_completed_publication_intent() {
        assert_ne!(unsafe { libc::geteuid() }, 0);
        assert_eq!(recover_after_witness_rename(), Err(IdentityDenied));
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
