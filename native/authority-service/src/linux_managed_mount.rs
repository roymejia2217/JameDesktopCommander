//! Test-only admission evidence for a freshly provisioned private tmpfs.
//! The trusted hosted issuer controls the mount namespace and its ancestors.
//! This does NOT prove absence of aliases in other mount namespaces, persistent
//! storage, client provenance, or production authorization.
use crate::managed_mutation_contract::{valid_name, MutationError};
use rustix::fs::{
    openat2, statx, AtFlags, Mode, OFlags, ResolveFlags, StatxAttributes, StatxFlags, CWD,
};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MountIdentity {
    id: u64,
    dev: (u32, u32),
    inode: u64,
}

fn mount_identity(fd: &File, require_root: bool) -> Result<MountIdentity, MutationError> {
    let mask = StatxFlags::BASIC_STATS | StatxFlags::MNT_ID;
    let s = statx(fd, "", AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT, mask)
        .map_err(|_| MutationError::Denied)?;
    if s.stx_mask & mask.bits() != mask.bits()
        || s.stx_mnt_id == 0
        || (require_root
            && (!s.stx_attributes_mask.contains(StatxAttributes::MOUNT_ROOT)
                || !s.stx_attributes.contains(StatxAttributes::MOUNT_ROOT)))
    {
        return Err(MutationError::Denied);
    }
    Ok(MountIdentity {
        id: s.stx_mnt_id,
        dev: (s.stx_dev_major, s.stx_dev_minor),
        inode: s.stx_ino,
    })
}

// /proc/self/mountinfo correlates the retained handle with the current
// namespace. Reject any second view of its device, descendant mount,
// non-full root, or propagation link. Other namespaces remain an issuer gate.
fn check_topology(text: &str, id: u64, parent: u64, dev: (u32, u32)) -> Result<(), MutationError> {
    let mut found = false;
    for line in text.lines() {
        let (left, right) = line.split_once(" - ").ok_or(MutationError::Denied)?;
        let fields: Vec<_> = left.split_ascii_whitespace().collect();
        let tail: Vec<_> = right.split_ascii_whitespace().collect();
        if fields.len() < 6 || tail.len() != 3 {
            return Err(MutationError::Denied);
        }
        let mid: u64 = fields[0].parse().map_err(|_| MutationError::Denied)?;
        let pid: u64 = fields[1].parse().map_err(|_| MutationError::Denied)?;
        let (major, minor) = fields[2].split_once(':').ok_or(MutationError::Denied)?;
        let other: (u32, u32) = (
            major.parse().map_err(|_| MutationError::Denied)?,
            minor.parse().map_err(|_| MutationError::Denied)?,
        );
        if pid == id || (other == dev && mid != id) {
            return Err(MutationError::Denied);
        }
        if mid == id {
            let opts: Vec<_> = fields[5].split(',').collect();
            if found
                || pid != parent
                || other != dev
                || fields[3] != "/"
                || fields.len() != 6
                || tail[0] != "tmpfs"
                || !opts.contains(&"rw")
                || !opts.contains(&"nosuid")
                || !opts.contains(&"nodev")
            {
                return Err(MutationError::Denied);
            }
            found = true;
        }
    }
    if !found {
        return Err(MutationError::Denied);
    }
    Ok(())
}

fn current_topology(id: MountIdentity, parent: MountIdentity) -> Result<(), MutationError> {
    const LIMIT: u64 = 4 * 1024 * 1024;
    let mut text = String::new();
    File::open("/proc/self/mountinfo")
        .map_err(|_| MutationError::Denied)?
        .take(LIMIT + 1)
        .read_to_string(&mut text)
        .map_err(|_| MutationError::Denied)?;
    if text.len() as u64 > LIMIT {
        return Err(MutationError::Denied);
    }
    check_topology(&text, id.id, parent.id, id.dev)
}

pub(super) struct VerifiedMount {
    parent: File,
    root: File,
    root_path: PathBuf,
    leaf: String,
    identity: MountIdentity,
    parent_identity: MountIdentity,
}
impl VerifiedMount {
    // Fixture only: the path comes from a trusted administrator-created
    // harness, not a client. The immediate parent is retained and must be
    // root-owned and non-writable by non-root identities.
    pub(super) fn open(path: &Path) -> Result<Self, MutationError> {
        crate::verify_service_identity().map_err(|_| MutationError::Denied)?;
        if !path.is_absolute() {
            return Err(MutationError::Denied);
        }
        let leaf = path
            .file_name()
            .and_then(|p| p.to_str())
            .filter(|p| valid_name(p))
            .ok_or(MutationError::Denied)?;
        let parent_path = path.parent().ok_or(MutationError::Denied)?;
        let parent = File::from(
            openat2(
                CWD,
                parent_path,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|_| MutationError::Denied)?,
        );
        let root = Self::open_child(&parent, leaf)?;
        let identity = mount_identity(&root, true)?;
        let parent_identity = mount_identity(&parent, false)?;
        if identity.dev == parent_identity.dev || identity.id == parent_identity.id {
            return Err(MutationError::Denied);
        }
        let result = Self {
            parent,
            root,
            root_path: path.to_owned(),
            leaf: leaf.to_owned(),
            identity,
            parent_identity,
        };
        result.revalidate()?;
        Ok(result)
    }
    fn open_child(parent: &File, leaf: &str) -> Result<File, MutationError> {
        Ok(File::from(
            openat2(
                parent,
                leaf,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|_| MutationError::Denied)?,
        ))
    }
    pub(super) fn revalidate(&self) -> Result<(), MutationError> {
        crate::verify_service_identity().map_err(|_| MutationError::Denied)?;
        let pm = self.parent.metadata().map_err(|_| MutationError::Denied)?;
        let rm = self.root.metadata().map_err(|_| MutationError::Denied)?;
        // Actual service credentials already verified above.
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        if !pm.is_dir()
            || pm.uid() != 0
            || pm.mode() & 0o022 != 0
            || !rm.is_dir()
            || rm.uid() != uid
            || rm.gid() != gid
            || rm.mode() & 0o7777 != 0o700
        {
            return Err(MutationError::Denied);
        }
        if mount_identity(&self.parent, false)? != self.parent_identity
            || mount_identity(&self.root, true)? != self.identity
            || mount_identity(&Self::open_child(&self.parent, &self.leaf)?, true)? != self.identity
        {
            return Err(MutationError::Denied);
        }
        let path_root = File::from(
            openat2(
                CWD,
                &self.root_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|_| MutationError::Denied)?,
        );
        if mount_identity(&path_root, true)? != self.identity {
            return Err(MutationError::Denied);
        }
        current_topology(self.identity, self.parent_identity)
    }
    pub(super) fn root_handle(&self) -> Result<File, MutationError> {
        self.revalidate()?;
        self.root.try_clone().map_err(|_| MutationError::Denied)
    }
    // SQLite uses a pathname-based VFS. Validate the private fixed path
    // from the retained mount first; this is only safe under the fixture's
    // exclusive principal and trusted ancestor/topology assumptions.
    pub(super) fn journal_path(&self) -> Result<PathBuf, MutationError> {
        self.revalidate()?;
        let dir = File::from(
            openat2(
                &self.root,
                ".jdc-state",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )
            .map_err(|_| MutationError::Denied)?,
        );
        let dm = dir.metadata().map_err(|_| MutationError::Denied)?;
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        if dm.uid() != uid || dm.gid() != gid || dm.mode() & 0o7777 != 0o700 {
            return Err(MutationError::Denied);
        }
        for (name, required) in [("policy.sqlite3", true), ("policy.sqlite3-journal", false)] {
            match openat2(
                &dir,
                name,
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            ) {
                Ok(fd) => {
                    let meta = File::from(fd)
                        .metadata()
                        .map_err(|_| MutationError::Denied)?;
                    if !meta.is_file()
                        || meta.uid() != uid
                        || meta.gid() != gid
                        || meta.nlink() != 1
                        || meta.mode() & 0o7777 != 0o600
                    {
                        return Err(MutationError::Denied);
                    }
                }
                Err(rustix::io::Errno::NOENT) if !required => {}
                Err(_) => return Err(MutationError::Denied),
            }
        }
        Ok(self.root_path.join(".jdc-state/policy.sqlite3"))
    }
}

#[path = "linux_managed_mount_tests.rs"]
mod tests;
