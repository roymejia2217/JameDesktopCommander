//! Linux-only protected-directory transaction feasibility. NON-SHIPPING.
//! No public service/CLI calls this code. Advisory same-UID locks do not
//! protect against an actively malicious process running as the same UID.
use rustix::fs::{self as osfs, AtFlags, Mode, OFlags, RenameFlags};
use rustix::process::geteuid;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

const LOCK: &str = ".jdc-rot-lock";
const JOURNAL: &str = ".jdc-rot-journal";
const NEXT: &str = ".jdc-rot-next";
const PREFIX: &str = ".jdc-rot-stage-";
const MAX_KEY: usize = 8192;
const MAX_JOURNAL: u64 = 1024;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RotationDenied;
impl std::fmt::Display for RotationDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Local credential transaction denied.")
    }
}
impl std::error::Error for RotationDenied {}
type Result<T> = std::result::Result<T, RotationDenied>;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RecoveryOutcome {
    PriorFileRestoredProviderUnverified,
    ConfirmedCredentialRetainedProviderUnverified,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Phase {
    Creating,
    Prepared,
    Committed,
}
impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Prepared => "prepared",
            Self::Committed => "committed",
        }
    }
}

#[derive(Clone)]
struct Journal {
    phase: Phase,
    target: String,
    stage: String,
    old_dev: u64,
    old_ino: u64,
    new_dev: u64,
    new_ino: u64,
}
impl Journal {
    fn encode(&self) -> String {
        format!(
            "JDC-ROT-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.phase.as_str(),
            self.target,
            self.stage,
            self.old_dev,
            self.old_ino,
            self.new_dev,
            self.new_ino
        )
    }
    fn decode(input: &str) -> Result<Self> {
        let lines: Vec<_> = input.lines().collect();
        if lines.len() != 8 || !input.ends_with('\n') || lines[0] != "JDC-ROT-v1" {
            return Err(RotationDenied);
        }
        let phase = match lines[1] {
            "creating" => Phase::Creating,
            "prepared" => Phase::Prepared,
            "committed" => Phase::Committed,
            _ => return Err(RotationDenied),
        };
        let target = lines[2];
        if target.is_empty()
            || target == "."
            || target == ".."
            || target.contains('/')
            || target.contains('\\')
            || target.bytes().any(|b| b < 0x20 || b == 0x7f)
            || target == LOCK
            || target == JOURNAL
            || target == NEXT
            || target.starts_with(PREFIX)
        {
            return Err(RotationDenied);
        }
        let stage = lines[3];
        if !stage.starts_with(PREFIX)
            || stage.len() != PREFIX.len() + 32
            || !stage[PREFIX.len()..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(RotationDenied);
        }
        let read_num = |text: &str| text.parse::<u64>().map_err(|_| RotationDenied);
        Ok(Self {
            phase,
            target: target.to_owned(),
            stage: stage.to_owned(),
            old_dev: read_num(lines[4])?,
            old_ino: read_num(lines[5])?,
            new_dev: read_num(lines[6])?,
            new_ino: read_num(lines[7])?,
        })
    }
}

fn uid() -> Result<u32> {
    let id = geteuid().as_raw();
    if id == 0 {
        return Err(RotationDenied);
    }
    Ok(id)
}

fn trusted_dir(file: &File, current_uid: u32, is_final: bool) -> Result<()> {
    let info = file.metadata().map_err(|_| RotationDenied)?;
    if !info.is_dir() || (info.uid() != 0 && info.uid() != current_uid) {
        return Err(RotationDenied);
    }
    let globally_writable = (info.mode() & 0o022) != 0;
    let root_owned_sticky = !is_final && info.uid() == 0 && (info.mode() & 0o1000) != 0;
    if globally_writable && !root_owned_sticky {
        return Err(RotationDenied);
    }
    if is_final && info.uid() != current_uid {
        return Err(RotationDenied);
    }
    Ok(())
}

fn verified_parent(path: &Path, current_uid: u32) -> Result<(File, String)> {
    if !path.is_absolute() {
        return Err(RotationDenied);
    }
    let leaf = path.file_name().ok_or(RotationDenied)?;
    let name = leaf.to_str().ok_or(RotationDenied)?;
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('\\')
        || name.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        || name == LOCK
        || name == JOURNAL
        || name == NEXT
        || name.starts_with(PREFIX)
    {
        return Err(RotationDenied);
    }
    let parent = path.parent().ok_or(RotationDenied)?;
    let mut dir = File::from(
        osfs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RotationDenied)?,
    );
    trusted_dir(&dir, current_uid, false)?;
    let components: Vec<_> = parent.components().collect();
    if components.first() != Some(&Component::RootDir) {
        return Err(RotationDenied);
    }
    let children: Vec<_> = components
        .iter()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(Ok(*name)),
            Component::RootDir => None,
            _ => Some(Err(RotationDenied)),
        })
        .collect::<Result<_>>()?;
    for (index, part) in children.iter().enumerate() {
        dir = File::from(
            osfs::openat(
                &dir,
                *part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| RotationDenied)?,
        );
        trusted_dir(&dir, current_uid, index + 1 == children.len())?;
    }
    if children.is_empty() {
        trusted_dir(&dir, current_uid, true)?;
    }
    Ok((dir, name.to_owned()))
}

fn read_private_file(dir: &File, name: &str, current_uid: u32) -> Result<File> {
    let f = File::from(
        osfs::openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RotationDenied)?,
    );
    let info = f.metadata().map_err(|_| RotationDenied)?;
    if !info.is_file()
        || info.uid() != current_uid
        || info.nlink() != 1
        || (info.mode() & 0o777) != 0o600
        || info.len() == 0
        || info.len() > MAX_KEY as u64
    {
        return Err(RotationDenied);
    }
    Ok(f)
}

fn create_private(dir: &File, name: &str) -> Result<File> {
    let fd = osfs::openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| RotationDenied)?;
    Ok(File::from(fd))
}

fn open_lock(dir: &File, current_uid: u32) -> Result<File> {
    let descriptor = osfs::openat(
        dir,
        LOCK,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .or_else(|_| {
        osfs::openat(
            dir,
            LOCK,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
    })
    .map_err(|_| RotationDenied)?;
    let file = File::from(descriptor);
    let info = file.metadata().map_err(|_| RotationDenied)?;
    if !info.is_file()
        || info.uid() != current_uid
        || info.nlink() != 1
        || (info.mode() & 0o777) != 0o600
    {
        return Err(RotationDenied);
    }
    file.try_lock().map_err(|_| RotationDenied)?;
    Ok(file)
}

fn exists(dir: &File, name: &str) -> Result<bool> {
    match osfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(_) => Err(RotationDenied),
    }
}
fn remove(dir: &File, name: &str) -> Result<()> {
    osfs::unlinkat(dir, name, AtFlags::empty()).map_err(|_| RotationDenied)
}
fn sync_dir(dir: &File) -> Result<()> {
    dir.sync_all().map_err(|_| RotationDenied)
}
fn rename(dir: &File, src: &str, dest: &str) -> Result<()> {
    osfs::renameat(dir, src, dir, dest).map_err(|_| RotationDenied)
}
fn exchange(dir: &File, a: &str, b: &str) -> Result<()> {
    osfs::renameat_with(dir, a, dir, b, RenameFlags::EXCHANGE).map_err(|_| RotationDenied)
}
fn same_inode(file: &File, dev: u64, ino: u64) -> Result<bool> {
    let m = file.metadata().map_err(|_| RotationDenied)?;
    Ok(m.dev() == dev && m.ino() == ino)
}

fn read_journal(dir: &File, current_uid: u32) -> Result<Journal> {
    let file = File::from(
        osfs::openat(
            dir,
            JOURNAL,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RotationDenied)?,
    );
    let meta = file.metadata().map_err(|_| RotationDenied)?;
    if !meta.is_file()
        || meta.uid() != current_uid
        || meta.nlink() != 1
        || (meta.mode() & 0o777) != 0o600
        || meta.len() == 0
        || meta.len() > MAX_JOURNAL
    {
        return Err(RotationDenied);
    }
    let mut input = String::new();
    file.take(MAX_JOURNAL + 1)
        .read_to_string(&mut input)
        .map_err(|_| RotationDenied)?;
    if input.len() > MAX_JOURNAL as usize {
        return Err(RotationDenied);
    }
    Journal::decode(&input)
}
fn write_initial_journal(dir: &File, j: &Journal) -> Result<()> {
    let mut f = create_private(dir, JOURNAL)?;
    f.write_all(j.encode().as_bytes())
        .map_err(|_| RotationDenied)?;
    f.sync_all().map_err(|_| RotationDenied)?;
    sync_dir(dir)
}
fn replace_journal(dir: &File, j: &Journal) -> Result<()> {
    let mut next = create_private(dir, NEXT)?;
    next.write_all(j.encode().as_bytes())
        .map_err(|_| RotationDenied)?;
    next.sync_all().map_err(|_| RotationDenied)?;
    // NEXT and JOURNAL are in the same pinned OS-owned directory.
    rename(dir, NEXT, JOURNAL)?;
    sync_dir(dir)
}
fn cleanup_journal(dir: &File) -> Result<()> {
    if exists(dir, NEXT)? {
        remove(dir, NEXT)?;
    }
    remove(dir, JOURNAL)?;
    sync_dir(dir)
}
fn inspect_stage(dir: &File, stage: &str, current_uid: u32) -> Result<Option<File>> {
    if !exists(dir, stage)? {
        return Ok(None);
    }
    let f = File::from(
        osfs::openat(
            dir,
            stage,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RotationDenied)?,
    );
    let m = f.metadata().map_err(|_| RotationDenied)?;
    if !m.is_file()
        || m.uid() != current_uid
        || m.nlink() != 1
        || (m.mode() & 0o777) != 0o600
        || m.len() > MAX_KEY as u64
    {
        return Err(RotationDenied);
    }
    Ok(Some(f))
}
fn restore_or_finish(dir: &File, target: &str, uid: u32) -> Result<RecoveryOutcome> {
    let j = read_journal(dir, uid)?;
    if j.target != target {
        return Err(RotationDenied);
    }
    let target_file = read_private_file(dir, target, uid)?;
    let stage_file = inspect_stage(dir, &j.stage, uid)?;
    let old_target = same_inode(&target_file, j.old_dev, j.old_ino)?;
    let new_target = same_inode(&target_file, j.new_dev, j.new_ino)?;
    match j.phase {
        Phase::Creating => {
            if !old_target {
                return Err(RotationDenied);
            }
            if stage_file.is_some() {
                remove(dir, &j.stage)?;
            }
        }
        Phase::Prepared => {
            let stage = stage_file.ok_or(RotationDenied)?;
            if old_target && same_inode(&stage, j.new_dev, j.new_ino)? {
                // Exchange not published: remove the newly staged credential.
            } else if new_target && same_inode(&stage, j.old_dev, j.old_ino)? {
                exchange(dir, &j.stage, target)?;
                sync_dir(dir)?;
            } else {
                // Never guess after an unknown external mutation.
                return Err(RotationDenied);
            }
            remove(dir, &j.stage)?;
        }
        Phase::Committed => {
            // The authenticated confirmation was durably recorded already.
            // After a crash during cleanup we must NOT revert the current key.
            if !new_target {
                return Err(RotationDenied);
            }
            if let Some(stage) = stage_file {
                if !same_inode(&stage, j.old_dev, j.old_ino)? {
                    return Err(RotationDenied);
                }
                remove(dir, &j.stage)?;
            }
            sync_dir(dir)?;
            cleanup_journal(dir)?;
            return Ok(RecoveryOutcome::ConfirmedCredentialRetainedProviderUnverified);
        }
    }
    sync_dir(dir)?;
    cleanup_journal(dir)?;
    Ok(RecoveryOutcome::PriorFileRestoredProviderUnverified)
}

/// Handle-based Linux file transaction, isolated from operator CLI and MCP.
///
/// Nothing here authenticates the installed systemd unit, provider identity,
/// or UI caller. A privileged product adapter MUST supply that authority
/// before calling this primitive. Passing an absolute path isn't authority.
pub struct LocalFileRotation {
    parent: File,
    _lease: File,
    target: String,
    j: Journal,
    published: bool,
    terminal: bool,
}
impl LocalFileRotation {
    /// Prepare a private candidate and a durable journal *before* publishing.
    /// The borrowed byte slice is always best-effort erased before returning.
    pub fn begin(target: &Path, secret: &mut [u8]) -> Result<Self> {
        let result = Self::begin_inner(target, secret);
        secret.fill(0);
        result
    }
    fn begin_inner(target: &Path, secret: &[u8]) -> Result<Self> {
        if secret.is_empty()
            || secret.len() > MAX_KEY
            || secret.iter().any(|b| *b < 0x20 || *b == 0x7f)
        {
            return Err(RotationDenied);
        }
        let current_uid = uid()?;
        let (parent, target) = verified_parent(target, current_uid)?;
        let lease = open_lock(&parent, current_uid)?;
        if exists(&parent, JOURNAL)? || exists(&parent, NEXT)? {
            return Err(RotationDenied);
        }
        let prior = read_private_file(&parent, &target, current_uid)?;
        let old = prior.metadata().map_err(|_| RotationDenied)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| RotationDenied)?;
        let mut stage = String::from(PREFIX);
        for b in nonce {
            stage.push_str(&format!("{b:02x}"));
        }
        let mut journal = Journal {
            phase: Phase::Creating,
            target: target.clone(),
            stage: stage.clone(),
            old_dev: old.dev(),
            old_ino: old.ino(),
            new_dev: 0,
            new_ino: 0,
        };
        // Crash before stage creation leaves no extra plaintext candidate.
        write_initial_journal(&parent, &journal)?;
        let mut f = create_private(&parent, &stage)?;
        f.write_all(secret).map_err(|_| RotationDenied)?;
        f.sync_all().map_err(|_| RotationDenied)?;
        let info = f.metadata().map_err(|_| RotationDenied)?;
        if info.uid() != current_uid
            || info.nlink() != 1
            || (info.mode() & 0o777) != 0o600
            || info.len() != secret.len() as u64
        {
            return Err(RotationDenied);
        }
        journal.new_dev = info.dev();
        journal.new_ino = info.ino();
        journal.phase = Phase::Prepared;
        replace_journal(&parent, &journal)?;
        Ok(Self {
            parent,
            _lease: lease,
            target,
            j: journal,
            published: false,
            terminal: false,
        })
    }

    /// Atomically swap the old/new inode in the pinned parent directory.
    /// This is NOT a provider-authenticated service handover.
    pub fn publish(&mut self) -> Result<()> {
        if self.terminal || self.published {
            return Err(RotationDenied);
        }
        let current_uid = uid()?;
        let old = read_private_file(&self.parent, &self.target, current_uid)?;
        let new = read_private_file(&self.parent, &self.j.stage, current_uid)?;
        if !same_inode(&old, self.j.old_dev, self.j.old_ino)?
            || !same_inode(&new, self.j.new_dev, self.j.new_ino)?
        {
            return Err(RotationDenied);
        }
        exchange(&self.parent, &self.j.stage, &self.target)?;
        self.published = true;
        sync_dir(&self.parent)
    }

    /// Called ONLY after the operator adapter independently witnesses fresh
    /// authenticated control-plane polling and verifies the registered target.
    pub fn confirm(&mut self) -> Result<()> {
        if self.terminal || !self.published {
            return Err(RotationDenied);
        }
        let current_uid = uid()?;
        let target = read_private_file(&self.parent, &self.target, current_uid)?;
        let old = read_private_file(&self.parent, &self.j.stage, current_uid)?;
        if !same_inode(&target, self.j.new_dev, self.j.new_ino)?
            || !same_inode(&old, self.j.old_dev, self.j.old_ino)?
        {
            return Err(RotationDenied);
        }
        let mut committed = self.j.clone();
        committed.phase = Phase::Committed;
        replace_journal(&self.parent, &committed)?;
        self.j = committed;
        remove(&self.parent, &self.j.stage)?;
        sync_dir(&self.parent)?;
        cleanup_journal(&self.parent)?;
        self.terminal = true;
        Ok(())
    }

    /// Restore the prior inode after a failed provider authentication.
    /// Recovery does not prove that the previous provider key is still valid.
    pub fn rollback(&mut self) -> Result<()> {
        if self.terminal {
            return Err(RotationDenied);
        }
        match restore_or_finish(&self.parent, &self.target, uid()?)? {
            RecoveryOutcome::PriorFileRestoredProviderUnverified => {
                self.terminal = true;
                Ok(())
            }
            RecoveryOutcome::ConfirmedCredentialRetainedProviderUnverified => Err(RotationDenied),
        }
    }
}

/// Explicit, exclusive local crash recovery. Does not invoke a service or
/// claim that any credential has been accepted by the provider.
pub fn recover_local_file(target: &Path) -> Result<RecoveryOutcome> {
    let current_uid = uid()?;
    let (dir, name) = verified_parent(target, current_uid)?;
    let _lock = open_lock(&dir, current_uid)?;
    restore_or_finish(&dir, &name, current_uid)
}
