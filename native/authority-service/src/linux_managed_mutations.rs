//! Native, nonshipping mutation engine for a future admitted managed volume.
//! This test-only module does NOT admit a volume, authenticate a client, or
//! establish durable authority. Its flat object namespace is deliberate.
//! Exclusive mutation custody is an external prerequisite; flock coordinates
//! cooperating instances, not hostile processes with the broker's rights.
use crate::{
    managed_mutation_contract::{valid_name, MutationError, Operation, MAX_BYTES, STAGE},
    policy_epoch::{PolicyFence, ReadTicket},
};
use rustix::{
    fs::{
        fchmod, flock, openat2, renameat, renameat_with, statat, unlinkat, AtFlags, FlockOperation,
        Mode, OFlags, RenameFlags, ResolveFlags,
    },
    io::Errno,
};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

// Native syscall boundary: real kernel operations by default; tests inject
// errors at the syscall result boundary without replacing the filesystem.
trait NativeIo: Send + Sync {
    fn rename(&self, root: &File, from: &str, to: &str, replace: bool) -> rustix::io::Result<()> {
        if replace {
            renameat(root, from, root, to)
        } else {
            renameat_with(root, from, root, to, RenameFlags::NOREPLACE)
        }
    }
    fn write_stage(&self, file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
        file.write_all(bytes)
    }
    fn sync_stage(&self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }
    fn cleanup(&self, root: &File) -> rustix::io::Result<()> {
        unlinkat(root, STAGE, AtFlags::empty())
    }
    fn sync_root(&self, root: &File) -> std::io::Result<()> {
        root.sync_all()
    }
}
struct SystemIo;
impl NativeIo for SystemIo {}

pub(super) struct Domain {
    root: File,
    io: Box<dyn NativeIo>,
    serializer: Mutex<()>,
    policy: PolicyFence,
    recovery: AtomicBool,
}

fn resolve() -> ResolveFlags {
    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV
}

fn read_target(root: &File, name: &str) -> Result<File, MutationError> {
    if !valid_name(name) {
        return Err(MutationError::Denied);
    }
    let file = File::from(
        openat2(
            root,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            resolve(),
        )
        .map_err(|_| MutationError::Denied)?,
    );
    let meta = file.metadata().map_err(|_| MutationError::Denied)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_BYTES as u64 {
        return Err(MutationError::Denied);
    }
    Ok(file)
}

fn same_target(root: &File, name: &str, retained: &File) -> Result<(), MutationError> {
    let expected = retained.metadata().map_err(|_| MutationError::Denied)?;
    let actual = read_target(root, name)?
        .metadata()
        .map_err(|_| MutationError::Denied)?;
    if expected.dev() != actual.dev()
        || expected.ino() != actual.ino()
        || expected.nlink() != 1
        || expected.len() != actual.len()
    {
        return Err(MutationError::Denied);
    }
    Ok(())
}

// Exactly one reserved staging entry under the retained private directory.
// Crash leftovers must be reconciled, never silently removed or overwritten.
struct Stage<'a> {
    domain: &'a Domain,
    file: File,
    cleanup_on_drop: bool,
}
impl Stage<'_> {
    fn verify_entry(&self) -> Result<(), MutationError> {
        let result = (|| {
            let held = self.file.metadata().ok()?;
            let entry = statat(&self.domain.root, STAGE, AtFlags::SYMLINK_NOFOLLOW).ok()?;
            (held.is_file()
                && held.nlink() == 1
                && entry.st_dev == held.dev()
                && entry.st_ino == held.ino()
                && entry.st_nlink == 1)
                .then_some(())
        })();
        if result.is_none() {
            self.domain.recovery.store(true, Ordering::Release);
            return Err(MutationError::RecoveryRequired);
        }
        Ok(())
    }
}
impl Drop for Stage<'_> {
    fn drop(&mut self) {
        // Do not unlink a substituted entry. Identity rechecking is defense
        // in depth; the independently enforced exclusive custody is essential.
        if self.cleanup_on_drop
            && (self.verify_entry().is_err() || self.domain.io.cleanup(&self.domain.root).is_err())
        {
            self.domain.recovery.store(true, Ordering::Release);
        }
    }
}

enum Prepared<'a> {
    Publish {
        name: &'a str,
        expected: Option<File>,
        stage: Stage<'a>,
    },
    Move {
        from: &'a str,
        to: &'a str,
        expected: File,
    },
}

impl Domain {
    pub(super) fn new_fixture(root: File, revision: u64) -> Result<Self, MutationError> {
        Self::new_fixture_with(root, || Ok((revision, ()))).map(|(domain, ())| domain)
    }

    // Open the journal only after acquiring the exclusive native domain lock.
    pub(super) fn new_fixture_with<T>(
        root: File,
        open_state: impl FnOnce() -> Result<(u64, T), MutationError>,
    ) -> Result<(Self, T), MutationError> {
        // Independently open the retained directory so a duplicated input
        // file description cannot bypass the cooperating instance lock.
        let root = File::from(
            openat2(
                &root,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                resolve(),
            )
            .map_err(|_| MutationError::Denied)?,
        );
        let meta = root.metadata().map_err(|_| MutationError::Denied)?;
        if !meta.is_dir() || meta.mode() & 0o777 != 0o700 {
            return Err(MutationError::Denied);
        }
        flock(&root, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| MutationError::Denied)?;
        let (revision, state) = open_state()?;
        Ok((
            Self {
                root,
                io: Box::new(SystemIo),
                serializer: Mutex::new(()),
                policy: PolicyFence::new(revision).map_err(|_| MutationError::Denied)?,
                recovery: AtomicBool::new(false),
            },
            state,
        ))
    }

    pub(super) fn issue(&self) -> Result<ReadTicket, MutationError> {
        self.policy.issue_read().map_err(|_| MutationError::Denied)
    }

    fn require_clear_stage(&self) -> Result<(), MutationError> {
        if self.recovery.load(Ordering::Acquire) {
            return Err(MutationError::RecoveryRequired);
        }
        match statat(&self.root, STAGE, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => Ok(()),
            _ => Err(MutationError::RecoveryRequired),
        }
    }

    fn stage<'a>(&'a self, bytes: &[u8]) -> Result<Stage<'a>, MutationError> {
        if bytes.len() > MAX_BYTES {
            return Err(MutationError::Denied);
        }
        let file = File::from(
            openat2(
                &self.root,
                STAGE,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
                resolve(),
            )
            .map_err(|e| {
                if e == Errno::EXIST {
                    MutationError::RecoveryRequired
                } else {
                    MutationError::Denied
                }
            })?,
        );
        let mut stage = Stage {
            domain: self,
            file,
            cleanup_on_drop: true,
        };
        // The open mode is filtered by umask. Set the contract's private mode
        // through the retained descriptor, never by reopening the name.
        fchmod(&stage.file, Mode::RUSR | Mode::WUSR).map_err(|_| MutationError::Denied)?;
        self.io
            .write_stage(&mut stage.file, bytes)
            .map_err(|_| MutationError::Denied)?;
        self.io
            .sync_stage(&stage.file)
            .map_err(|_| MutationError::Denied)?;
        Ok(stage)
    }

    fn prepare<'a>(&'a self, operation: Operation<'a>) -> Result<Prepared<'a>, MutationError> {
        self.require_clear_stage()?;
        match operation {
            Operation::Create { name, bytes } => {
                if !valid_name(name) {
                    return Err(MutationError::Denied);
                }
                Ok(Prepared::Publish {
                    name,
                    expected: None,
                    stage: self.stage(bytes)?,
                })
            }
            Operation::Rewrite { name, bytes } => {
                let expected = read_target(&self.root, name)?;
                Ok(Prepared::Publish {
                    name,
                    expected: Some(expected),
                    stage: self.stage(bytes)?,
                })
            }
            Operation::Append { name, bytes } => {
                if bytes.len() > MAX_BYTES {
                    return Err(MutationError::Denied);
                }
                let mut expected = read_target(&self.root, name)?;
                let mut contents = Vec::new();
                (&mut expected)
                    .take((MAX_BYTES + 1) as u64)
                    .read_to_end(&mut contents)
                    .map_err(|_| MutationError::Denied)?;
                if contents.len() > MAX_BYTES - bytes.len() {
                    return Err(MutationError::Denied);
                }
                contents.extend_from_slice(bytes);
                // Transactional append replaces the inode; not a claim of
                // preserving arbitrary existing-file metadata or handles.
                Ok(Prepared::Publish {
                    name,
                    expected: Some(expected),
                    stage: self.stage(&contents)?,
                })
            }
            Operation::Rename { from, to } => {
                if !valid_name(to) || from == to {
                    return Err(MutationError::Denied);
                }
                let expected = read_target(&self.root, from)?;
                Ok(Prepared::Move { from, to, expected })
            }
        }
    }

    fn commit(&self, prepared: Prepared<'_>, cancelled: &AtomicBool) -> Result<(), MutationError> {
        match prepared {
            Prepared::Publish {
                name,
                expected,
                mut stage,
            } => {
                if let Some(ref file) = expected {
                    same_target(&self.root, name, file)?;
                }
                stage.verify_entry()?;
                // Cancellation checked at commit admission. Once the OS
                // rename is entered the outcome must be resolved, not retried.
                if cancelled.load(Ordering::Acquire) {
                    return Err(MutationError::Denied);
                }
                match self.io.rename(&self.root, STAGE, name, expected.is_some()) {
                    Ok(()) => stage.cleanup_on_drop = false,
                    Err(Errno::EXIST) if expected.is_none() => {
                        return Err(MutationError::Collision);
                    }
                    Err(_) => {
                        // The namespace operation may already have committed.
                        // Preserve any remaining staging evidence and block the
                        // live domain until an external recovery reconciles it.
                        stage.cleanup_on_drop = false;
                        self.recovery.store(true, Ordering::Release);
                        return Err(MutationError::RecoveryRequired);
                    }
                }
            }
            Prepared::Move { from, to, expected } => {
                same_target(&self.root, from, &expected)?;
                if cancelled.load(Ordering::Acquire) {
                    return Err(MutationError::Denied);
                }
                match self.io.rename(&self.root, from, to, false) {
                    Ok(()) => {}
                    Err(Errno::EXIST) => return Err(MutationError::Collision),
                    Err(_) => {
                        self.recovery.store(true, Ordering::Release);
                        return Err(MutationError::RecoveryRequired);
                    }
                }
            }
        }
        // Visibility already committed. Failed durability acknowledgement
        // is uncertain, not a denial and not permission to retry.
        if self.io.sync_root(&self.root).is_err() {
            self.recovery.store(true, Ordering::Release);
            return Err(MutationError::RecoveryRequired);
        }
        Ok(())
    }

    fn execute(
        &self,
        ticket: &ReadTicket,
        operation: Operation<'_>,
        cancelled: &AtomicBool,
    ) -> Result<(), MutationError> {
        self.execute_with(ticket, operation, cancelled, || {})
    }

    pub(super) fn execute_with(
        &self,
        ticket: &ReadTicket,
        operation: Operation<'_>,
        cancelled: &AtomicBool,
        before_commit: impl FnOnce(),
    ) -> Result<(), MutationError> {
        let _serial = self
            .serializer
            .lock()
            .map_err(|_| MutationError::RecoveryRequired)?;
        let result = self
            .policy
            .prepare_and_commit_once(
                ticket,
                || {
                    if cancelled.load(Ordering::Acquire) {
                        return Err(MutationError::Denied);
                    }
                    let prepared = self.prepare(operation)?;
                    before_commit();
                    Ok(prepared)
                },
                |prepared| self.commit(prepared, cancelled),
            )
            .map_err(|_| MutationError::Denied);
        if self.recovery.load(Ordering::Acquire) {
            return Err(MutationError::RecoveryRequired);
        }
        result?
    }
}

#[path = "linux_managed_mutations_tests.rs"]
mod tests;
