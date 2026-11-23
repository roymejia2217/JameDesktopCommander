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

/// Synchronizes the *entire* authorized operation (including transport
/// disclosure) against revocation, not only a pre-I/O version check.
/// No polling; revocation waits for operations already admitted.
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

    /// Claim exactly once before any native operation; stale, revoked, wrong
    /// issuer and replayed claims are rejected before invoking the callback.
    pub fn execute_once<T>(
        &self,
        ticket: &ReadTicket,
        operation: impl FnOnce() -> T,
    ) -> Result<T, EpochDenied> {
        if ticket.spent.swap(true, Ordering::AcqRel)
            || !Arc::ptr_eq(&self.identity, &ticket.identity)
        {
            return Err(EpochDenied);
        }
        self.execute(ticket.revision, operation)
    }

    /// Hold a shared read lock through the caller's bounded native I/O AND
    /// its response disclosure. The closure must not call revoke/advance.
    /// On return from revoke(), no previously admitted operation is executing.
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
