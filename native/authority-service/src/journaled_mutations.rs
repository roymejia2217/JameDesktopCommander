//! Nonshipping, process-exit-scoped integration of the native engines and
//! existing SQLite journal. Fixture paths are NOT admitted authority.
//! Exclusive native-domain ownership must also fence any trusted reconciler.
//! No runtime caller, policy advance, reconciliation, or power-loss guarantee.
#[cfg(target_os = "linux")]
use crate::linux_managed_mutations::Domain;
use crate::managed_mutation_contract::{valid_name, MutationError, Operation, MAX_BYTES};
#[cfg(windows)]
use crate::windows_managed_mutations::Domain;
use jdc_authority_store::mutation_journal::Snapshot;
use jdc_authority_store::mutation_journal::{Journal, Outcome, Phase};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

// Fixed acceptance schema; no runtime policy provisioning API.
fn provision_fixture_journal(
    conn: &rusqlite::Connection,
    domain: [u8; 32],
) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA application_id=0x4A444331;
         PRAGMA user_version=2;
         CREATE TABLE protected_state (slot INTEGER PRIMARY KEY CHECK(slot=1), domain BLOB NOT NULL CHECK(typeof(domain)='blob' AND length(domain)=32), epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32), sequence BLOB NOT NULL CHECK(typeof(sequence)='blob' AND length(sequence)=8), phase INTEGER NOT NULL CHECK(phase IN (0,1,2,3)), operation_epoch BLOB NOT NULL CHECK(typeof(operation_epoch)='blob' AND length(operation_epoch)=8), request_digest BLOB NOT NULL CHECK(typeof(request_digest)='blob' AND length(request_digest)=32));
         INSERT INTO protected_state VALUES(1,zeroblob(32),x'0000000000000001',zeroblob(32),zeroblob(8),0,zeroblob(8),zeroblob(32));"
    )?;
    conn.execute(
        "UPDATE protected_state SET domain=?1 WHERE slot=1",
        [domain.as_slice()],
    )?;
    Ok(())
}

fn request_digest(
    domain: [u8; 32],
    epoch: u64,
    sequence: u64,
    op: &Operation<'_>,
) -> Result<[u8; 32], MutationError> {
    let (tag, name, data, destination) = match op {
        Operation::Create { name, bytes } => (1u8, *name, *bytes, None),
        Operation::Append { name, bytes } => (2, *name, *bytes, None),
        Operation::Rewrite { name, bytes } => (3, *name, *bytes, None),
        Operation::Rename { from, to } => (4, *from, &[][..], Some(*to)),
    };
    if domain == [0; 32]
        || epoch == 0
        || sequence == 0
        || !valid_name(name)
        || data.len() > MAX_BYTES
        || destination.is_some_and(|name| !valid_name(name))
    {
        return Err(MutationError::Denied);
    }
    let mut h = Sha256::new();
    h.update(b"JDC managed mutation fixture v1\0");
    h.update(domain);
    h.update(epoch.to_be_bytes());
    h.update(sequence.to_be_bytes());
    h.update([tag]);
    // Length framing prevents ambiguity; never log content or store it in SQL.
    let mut field = |bytes: &[u8]| {
        h.update((bytes.len() as u32).to_be_bytes());
        h.update(bytes);
    };
    field(name.as_bytes());
    field(data);
    field(destination.unwrap_or("").as_bytes());
    Ok(h.finalize().into())
}

struct State {
    journal: Journal,
    uncertain: bool,
}
struct JournaledDomain {
    // Rust drops fields in declaration order. Keep the native owner lock
    // until the SQLite connection has closed.
    state: Mutex<State>,
    native: Domain,
    #[cfg(target_os = "linux")]
    admitted_mount: Option<crate::linux_managed_mount::VerifiedMount>,
    #[cfg(windows)]
    admitted_volume: Option<crate::windows_managed_volume::VerifiedVolume>,
    domain: [u8; 32],
    epoch: u64,
}

impl JournaledDomain {
    #[cfg(test)]
    fn open_fixture(root: &Path, db: &Path, domain: [u8; 32]) -> Result<Self, MutationError> {
        let journal =
            Journal::open_existing(db, domain).map_err(|_| MutationError::RecoveryRequired)?;
        let Snapshot { epoch, .. } = journal
            .snapshot()
            .map_err(|_| MutationError::RecoveryRequired)?;
        // Acquire the real native exclusive instance lock before admitting
        // any execution. The fixture does not establish protected custody.
        #[cfg(target_os = "linux")]
        let native = Domain::new_fixture(
            std::fs::File::open(root).map_err(|_| MutationError::Denied)?,
            epoch,
        )?;
        #[cfg(windows)]
        let native = Domain::new_fixture(root, epoch)?;
        Ok(Self {
            native,
            #[cfg(target_os = "linux")]
            admitted_mount: None,
            #[cfg(windows)]
            admitted_volume: None,
            domain,
            epoch,
            state: Mutex::new(State {
                journal,
                uncertain: false,
            }),
        })
    }

    #[cfg(target_os = "linux")]
    fn open_verified_linux(path: &Path, domain: [u8; 32]) -> Result<Self, MutationError> {
        use crate::linux_managed_mount::VerifiedMount;
        let mount = VerifiedMount::open(path)?;
        let (native, (journal, epoch)) = Domain::new_fixture_with(mount.root_handle()?, || {
            let db = mount.journal_path()?;
            let journal =
                Journal::open_existing(&db, domain).map_err(|_| MutationError::RecoveryRequired)?;
            let epoch = journal
                .snapshot()
                .map_err(|_| MutationError::RecoveryRequired)?
                .epoch;
            mount.revalidate()?;
            Ok((epoch, (journal, epoch)))
        })?;
        Ok(Self {
            native,
            admitted_mount: Some(mount),
            domain,
            epoch,
            state: Mutex::new(State {
                journal,
                uncertain: false,
            }),
        })
    }

    #[cfg(windows)]
    fn open_verified_windows(
        drive: &str,
        guid: &str,
        service: &str,
        owner: &str,
        domain: [u8; 32],
    ) -> Result<Self, MutationError> {
        use crate::windows_managed_volume::VerifiedVolume;
        let volume = VerifiedVolume::open(drive, guid, service, owner)?;
        let (native, (journal, epoch)) = Domain::new_fixture_with(volume.root_handle()?, || {
            let db = volume.journal_path()?;
            let journal = Journal::open_existing(&db, domain).map_err(|_| {
                eprintln!("T011_WINDOWS_DOMAIN_ADMISSION_DENIED check=journal-open");
                MutationError::RecoveryRequired
            })?;
            let epoch = journal
                .snapshot()
                .map_err(|_| {
                    eprintln!("T011_WINDOWS_DOMAIN_ADMISSION_DENIED check=journal-snapshot");
                    MutationError::RecoveryRequired
                })?
                .epoch;
            volume.revalidate()?;
            Ok((epoch, (journal, epoch)))
        })?;
        Ok(Self {
            native,
            admitted_volume: Some(volume),
            domain,
            epoch,
            state: Mutex::new(State {
                journal,
                uncertain: false,
            }),
        })
    }

    #[cfg(windows)]
    fn snapshot(&self) -> Result<Snapshot, crate::IdentityDenied> {
        self.state
            .lock()
            .map_err(|_| crate::IdentityDenied)?
            .journal
            .snapshot()
            .map_err(|_| crate::IdentityDenied)
    }

    // A single fixture owner serializes journal and engine as one logical
    // operation. No public path to native mutation bypasses this wrapper.
    // The unjournaled engines remain separate test-only component fixtures.
    fn execute(
        &self,
        epoch: u64,
        sequence: u64,
        op: Operation<'_>,
        cancelled: &AtomicBool,
        before_commit: impl FnOnce(),
        after_native: impl FnOnce(),
    ) -> Result<(), MutationError> {
        let digest = request_digest(self.domain, epoch, sequence, &op)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| MutationError::RecoveryRequired)?;
        if state.uncertain {
            return Err(MutationError::RecoveryRequired);
        }
        #[cfg(target_os = "linux")]
        if let Some(mount) = &self.admitted_mount {
            if mount.revalidate().is_err() {
                state.uncertain = true;
                return Err(MutationError::RecoveryRequired);
            }
        }
        #[cfg(windows)]
        if let Some(volume) = &self.admitted_volume {
            if volume.revalidate().is_err() {
                state.uncertain = true;
                return Err(MutationError::RecoveryRequired);
            }
        }
        let snapshot = match state.journal.snapshot() {
            Ok(s) => s,
            Err(_) => {
                state.uncertain = true;
                return Err(MutationError::RecoveryRequired);
            }
        };
        if snapshot.phase == Phase::Pending || snapshot.epoch != self.epoch {
            return Err(MutationError::RecoveryRequired);
        }
        if epoch != self.epoch
            || snapshot.sequence.checked_add(1) != Some(sequence)
            || cancelled.load(Ordering::Acquire)
        {
            return Err(MutationError::Denied);
        }
        let ticket = self.native.issue()?;
        // No native staging or mutation before the committed journal intent.
        if state.journal.begin(epoch, sequence, digest).is_err() {
            state.uncertain = true;
            return Err(MutationError::RecoveryRequired);
        }
        #[cfg(target_os = "linux")]
        let result = self
            .native
            .execute_with(&ticket, op, cancelled, before_commit);
        #[cfg(windows)]
        let result = self.native.execute(&ticket, op, cancelled, before_commit);
        // Test-only process-exit fault boundary. A panic poisons the owner
        // mutex and leaves the pending row for external reconciliation.
        after_native();
        #[cfg(target_os = "linux")]
        if let Some(mount) = &self.admitted_mount {
            if mount.revalidate().is_err() {
                state.uncertain = true;
                return Err(MutationError::RecoveryRequired);
            }
        }
        #[cfg(windows)]
        if let Some(volume) = &self.admitted_volume {
            if volume.revalidate().is_err() {
                state.uncertain = true;
                return Err(MutationError::RecoveryRequired);
            }
        }
        let outcome = match result {
            Ok(()) => Outcome::Committed,
            Err(MutationError::Denied | MutationError::Collision) => Outcome::Rejected,
            Err(MutationError::RecoveryRequired) => {
                state.uncertain = true;
                return Err(MutationError::RecoveryRequired);
            }
        };
        // Committed here means the native operation completed under the
        // fixture's process-termination model, not Windows volume power-loss
        // durability. No response precedes terminal persistence.
        if state
            .journal
            .finish(epoch, sequence, digest, outcome)
            .is_err()
        {
            state.uncertain = true;
            return Err(MutationError::RecoveryRequired);
        }
        result
    }
}

// Fixed, nonshipping request plan shared by the local SDK regression and
// the independently admitted SCM fixture. Never decode a caller's path
// into a native mutation capability.
#[cfg(windows)]
fn serve_fresh_sdk_mutations(
    domain: &JournaledDomain,
    root: &Path,
    pipe: &crate::windows_mutation_pipe::MutationPipe,
    child: std::os::windows::io::BorrowedHandle<'_>,
    sid: &[u8],
    custody: impl Fn() -> bool,
) -> Result<(), crate::IdentityDenied> {
    use crate::IdentityDenied;
    use std::{fs, time::Duration};

    let snapshot = || domain.snapshot();
    let initial = snapshot()?;
    if initial.epoch != domain.epoch
        || initial.phase == Phase::Pending
        || ["report.txt", "final.txt", "ungranted.txt"]
            .iter()
            .any(|name| !matches!(root.join(name).try_exists(), Ok(false)))
    {
        return Err(IdentityDenied);
    }
    for (index, (expected, operation)) in fixed_sdk_mutation_plan().into_iter().enumerate() {
        if !custody() {
            return Err(IdentityDenied);
        }
        pipe.challenge(child)?;
        let observed = pipe.receive(child, sid, 4096, Duration::from_secs(5))?;
        if observed != expected || !custody() || !pipe.commit_allowed(child, sid) {
            return Err(IdentityDenied);
        }
        if let Some(operation) = operation {
            let sequence = initial
                .sequence
                .checked_add(index as u64)
                .ok_or(IdentityDenied)?;
            let digest = request_digest(domain.domain, domain.epoch, sequence, &operation)
                .map_err(|_| IdentityDenied)?;
            let cancelled = AtomicBool::new(false);
            domain
                .execute(
                    domain.epoch,
                    sequence,
                    operation,
                    &cancelled,
                    || {
                        if !custody() || !pipe.commit_allowed(child, sid) {
                            cancelled.store(true, Ordering::Release);
                        }
                    },
                    || {},
                )
                .map_err(|_| IdentityDenied)?;
            let state = snapshot()?;
            if state.phase != Phase::Committed
                || state.sequence != sequence
                || state.request_digest != digest
            {
                return Err(IdentityDenied);
            }
            let (name, bytes): (&str, &[u8]) = match index {
                1 => ("report.txt", b"BEGIN"),
                2 => ("report.txt", b"BEGIN-APPEND"),
                3 => ("report.txt", b"REWRITE"),
                4 => ("final.txt", b"REWRITE"),
                5 => ("final.txt", b"REWRITE-LOST"),
                _ => return Err(IdentityDenied),
            };
            if fs::read(root.join(name)).map_err(|_| IdentityDenied)? != bytes {
                return Err(IdentityDenied);
            }
            if index != 5 {
                if !custody() || !pipe.commit_allowed(child, sid) {
                    return Err(IdentityDenied);
                }
                pipe.reply(child, sid, b'A')?;
            }
        } else {
            if snapshot()? != initial
                || root
                    .join("ungranted.txt")
                    .try_exists()
                    .map_err(|_| IdentityDenied)?
            {
                return Err(IdentityDenied);
            }
            pipe.reply(child, sid, b'D')?;
        }
    }
    if root
        .join("report.txt")
        .try_exists()
        .map_err(|_| IdentityDenied)?
        || snapshot()?.sequence != initial.sequence.checked_add(5).ok_or(IdentityDenied)?
    {
        return Err(IdentityDenied);
    }
    // Caller closes the single channel after the fifth terminal commit:
    // the SDK must report an unknown result and must never retry it.
    Ok(())
}

#[cfg(windows)]
fn serve_fresh_sdk_cancellation(
    domain: &JournaledDomain,
    root: &Path,
    pipe: &crate::windows_mutation_pipe::MutationPipe,
    child: std::os::windows::io::BorrowedHandle<'_>,
    sid: &[u8],
    custody: impl Fn() -> bool,
) -> Result<(), crate::IdentityDenied> {
    use crate::IdentityDenied;
    use std::time::Duration;
    let before = domain.snapshot()?;
    if !custody() || !matches!(root.join("cancelled.txt").try_exists(), Ok(false)) {
        return Err(IdentityDenied);
    }
    pipe.challenge(child)?;
    let observed = pipe.receive(child, sid, 4096, Duration::from_secs(5))?;
    if observed != sdk_mutation_payload(1, b"/managed/cancelled.txt", b"MUST-NOT-PUBLISH")
        || !custody()
        || !pipe.commit_allowed(child, sid)
    {
        return Err(IdentityDenied);
    }
    let sequence = before.sequence.checked_add(1).ok_or(IdentityDenied)?;
    let operation = Operation::Create {
        name: "cancelled.txt",
        bytes: b"MUST-NOT-PUBLISH",
    };
    let digest = request_digest(domain.domain, domain.epoch, sequence, &operation)
        .map_err(|_| IdentityDenied)?;
    let cancelled = AtomicBool::new(false);
    let mut observed_cancellation = false;
    let result = domain.execute(
        domain.epoch,
        sequence,
        operation,
        &cancelled,
        || {
            observed_cancellation = custody()
                && matches!(root.join(".jdc-stage").try_exists(), Ok(true))
                && matches!(root.join("cancelled.txt").try_exists(), Ok(false))
                && pipe.observe_staged_cancellation(child, sid).is_ok()
                && !pipe.commit_allowed(child, sid);
            // Never publish this scenario even if cancellation evidence is missing.
            cancelled.store(true, Ordering::Release);
        },
        || {},
    );
    let after = domain.snapshot()?;
    if !observed_cancellation
        || result != Err(MutationError::Denied)
        || after.phase != Phase::Rejected
        || after.sequence != sequence
        || after.epoch != before.epoch
        || after.request_digest != digest
        || !matches!(root.join("cancelled.txt").try_exists(), Ok(false))
        || !matches!(root.join(".jdc-stage").try_exists(), Ok(false))
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn sdk_mutation_payload(tag: u8, first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut data = vec![tag];
    for field in [first, second] {
        data.extend_from_slice(&(field.len() as u32).to_be_bytes());
        data.extend_from_slice(field);
    }
    data
}

fn fixed_sdk_mutation_plan() -> [(Vec<u8>, Option<Operation<'static>>); 6] {
    let payload = sdk_mutation_payload;
    [
        (payload(1, b"/managed/ungranted.txt", b"never"), None),
        (
            payload(1, b"/managed/report.txt", b"BEGIN"),
            Some(Operation::Create {
                name: "report.txt",
                bytes: b"BEGIN",
            }),
        ),
        (
            payload(2, b"/managed/report.txt", b"-APPEND"),
            Some(Operation::Append {
                name: "report.txt",
                bytes: b"-APPEND",
            }),
        ),
        (
            payload(1, b"/managed/report.txt", b"REWRITE"),
            Some(Operation::Rewrite {
                name: "report.txt",
                bytes: b"REWRITE",
            }),
        ),
        (
            payload(3, b"/managed/report.txt", b"/managed/final.txt"),
            Some(Operation::Rename {
                from: "report.txt",
                to: "final.txt",
            }),
        ),
        (
            payload(2, b"/managed/final.txt", b"-LOST"),
            Some(Operation::Append {
                name: "final.txt",
                bytes: b"-LOST",
            }),
        ),
    ]
}

#[cfg(all(windows, feature = "scm-storage-proof"))]
#[path = "windows_scm_admitted_storage.rs"]
mod scm_storage;
#[cfg(all(windows, feature = "scm-storage-proof"))]
pub use scm_storage::ScmAdmittedStorage;

#[cfg(test)]
#[path = "journaled_mutations_tests.rs"]
mod tests;
