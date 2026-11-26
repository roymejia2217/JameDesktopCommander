//! Nonshipping, process-exit-scoped integration of the native engines and
//! existing SQLite journal. Fixture paths are NOT admitted authority.
//! Exclusive native-domain ownership must also fence any trusted reconciler.
//! No runtime caller, policy advance, reconciliation, or power-loss guarantee.
#[cfg(target_os = "linux")]
use crate::linux_managed_mutations::Domain;
use crate::managed_mutation_contract::{valid_name, MutationError, Operation, MAX_BYTES};
#[cfg(windows)]
use crate::windows_managed_mutations::Domain;
use jdc_authority_store::mutation_journal::{Journal, Outcome, Phase, Snapshot};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

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
            let journal =
                Journal::open_existing(&db, domain).map_err(|_| MutationError::RecoveryRequired)?;
            let epoch = journal
                .snapshot()
                .map_err(|_| MutationError::RecoveryRequired)?
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

#[path = "journaled_mutations_tests.rs"]
mod tests;
