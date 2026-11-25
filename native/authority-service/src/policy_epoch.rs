//! Bounded-lifetime policy epoch fence for future native broker operations.
//! Not an authorization source: initial/advanced revisions MUST originate
//! from an authenticated and durable, rollback-protected service policy.
//! This does not grant a root, client, file, or installed-service permission.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EpochDenied;

struct State {
    revision: u64,
    active: bool,
}

/// Synchronizes committed operations and transport disclosure against
/// revocation, not only a pre-I/O version check. Read-only Linux preparation
/// may run outside the lock but cannot disclose after its epoch is revoked.
/// No polling; revocation waits for committed operations only.
pub struct PolicyFence {
    state: RwLock<State>,
    identity: Arc<()>,
}

/// A one-use, nonserializable operation claim. It is tied to the issuing
/// PolicyFence instance, not just a caller-reported numeric revision.
/// This is not an OS client credential or a filesystem capability.
pub struct ReadTicket {
    revision: u64,
    identity: Arc<()>,
    spent: AtomicBool,
}

impl PolicyFence {
    pub fn new(revision: u64) -> Result<Self, EpochDenied> {
        if revision == 0 {
            return Err(EpochDenied);
        }
        Ok(Self {
            state: RwLock::new(State {
                revision,
                active: true,
            }),
            identity: Arc::new(()),
        })
    }

    /// The trusted service creates a non-clonable ticket only *after*
    /// authenticating the caller and request. Issuance itself never proves
    /// that a caller is authorized to use the returned claim.
    pub fn issue_read(&self) -> Result<ReadTicket, EpochDenied> {
        let state = self.state.read().map_err(|_| EpochDenied)?;
        if !state.active {
            return Err(EpochDenied);
        }
        Ok(ReadTicket {
            revision: state.revision,
            identity: Arc::clone(&self.identity),
            spent: AtomicBool::new(false),
        })
    }

    fn claim(&self, ticket: &ReadTicket) -> Result<(), EpochDenied> {
        if ticket.spent.swap(true, Ordering::AcqRel)
            || !Arc::ptr_eq(&self.identity, &ticket.identity)
        {
            return Err(EpochDenied);
        }
        Ok(())
    }

    /// Claim exactly once before any native operation; stale, revoked, wrong
    /// issuer and replayed claims are rejected before invoking the callback.
    pub fn execute_once<T>(
        &self,
        ticket: &ReadTicket,
        operation: impl FnOnce() -> T,
    ) -> Result<T, EpochDenied> {
        self.claim(ticket)?;
        self.execute(ticket.revision, operation)
    }

    /// Read-only preparation stays inside the trusted service, without
    /// holding the revocation lock. It must not disclose bytes, mutate an
    /// object, or create externally usable authority. Revocation can finish
    /// while preparation is blocked; only a still-current epoch may commit
    /// the bounded disclosure. The spent ticket is never reusable.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_and_disclose_once<T, E>(
        &self,
        ticket: &ReadTicket,
        prepare: impl FnOnce() -> Result<T, E>,
        disclose: impl FnOnce(T) -> Result<(), E>,
    ) -> Result<Result<(), E>, EpochDenied> {
        self.claim(ticket)?;
        self.execute(ticket.revision, || ())?;
        let prepared = match prepare() {
            Ok(value) => value,
            Err(error) => return Ok(Err(error)),
        };
        self.execute(ticket.revision, || disclose(prepared))
    }

    /// Hold a shared read lock through the caller's bounded native I/O AND
    /// its response disclosure. The closure must not call revoke/advance.
    /// On return from revoke(), no previously committed disclosure is executing.
    fn execute<T>(
        &self,
        expected_revision: u64,
        operation: impl FnOnce() -> T,
    ) -> Result<T, EpochDenied> {
        let state = self.state.read().map_err(|_| EpochDenied)?;
        if !state.active || expected_revision == 0 || expected_revision != state.revision {
            return Err(EpochDenied);
        }
        Ok(operation())
    }

    /// Revocation linearizes only when all previously admitted operations
    /// finish their read-locked disclosure. Never claim that an in-flight
    /// operation is cancelled or its already-returned bytes are retracted.
    pub fn revoke(&self) -> Result<(), EpochDenied> {
        let mut state = self.state.write().map_err(|_| EpochDenied)?;
        state.active = false;
        Ok(())
    }

    /// Re-activation requires a strictly higher independently approved epoch;
    /// the old epoch can never be made current again in this process.
    /// Durable replay protection across restarts remains an external gate.
    pub fn advance(&self, new_revision: u64) -> Result<(), EpochDenied> {
        let mut state = self.state.write().map_err(|_| EpochDenied)?;
        if new_revision <= state.revision {
            return Err(EpochDenied);
        }
        state.revision = new_revision;
        state.active = true;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod staged_read_tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};

    #[test]
    fn revocation_and_advance_do_not_wait_for_uncommitted_read_preparation() {
        for advance in [false, true] {
            let policy = Arc::new(PolicyFence::new(1).unwrap());
            let ticket = policy.issue_read().unwrap();
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let worker_policy = Arc::clone(&policy);
            let worker = thread::spawn(move || {
                worker_policy.prepare_and_disclose_once(
                    &ticket,
                    || {
                        started_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok::<_, ()>(b"PRIVATE")
                    },
                    |_| panic!("revoked preparation must not disclose"),
                )
            });
            started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let (done_tx, done_rx) = mpsc::channel();
            let revoker = thread::spawn(move || {
                done_tx
                    .send(if advance {
                        policy.advance(2)
                    } else {
                        policy.revoke()
                    })
                    .unwrap();
            });
            let outcome = done_rx.recv_timeout(Duration::from_secs(2));
            release_tx.send(()).unwrap();
            assert_eq!(worker.join().unwrap(), Err(EpochDenied));
            revoker.join().unwrap();
            assert_eq!(outcome, Ok(Ok(())));
        }
    }
}
