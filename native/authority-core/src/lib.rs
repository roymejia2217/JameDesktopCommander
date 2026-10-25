//! Experimental in-process ordering primitive, not an OS-protected authority.
//! There is NO trusted epoch store, native capability binding or IPC peer identity.

use std::{cell::RefCell, sync::Mutex};

/// Denial by an in-process sequencing gate; not an OS authorization verdict.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Denied;

#[derive(Copy, Clone, Eq, PartialEq)]
enum Phase {
    Unavailable,
    Active,
    Closed,
}

struct State {
    last_epoch: u64,
    phase: Phase,
}

/// In-memory ordering only. NOT trusted persistent policy, OS identity, or
/// native filesystem confinement. Only a future protected broker may use it
/// after independently authenticating and durably committing an epoch.
///
/// A separate consumer MUST NOT be able to promote client-supplied data into
/// an active epoch. The trusted bootstrap path does not exist yet.
/// ```compile_fail
/// use jdc_authority_core::EpochArbiter;
/// let gate = EpochArbiter::new();
/// gate.accept_externally_committed_epoch(7).unwrap();
/// ```
pub struct EpochArbiter {
    state: Mutex<State>,
}

// A recursive call from an operation callback on the SAME thread would
// otherwise wait forever on this arbiter's non-reentrant mutex. Track only
// the identity of in-flight instances; another thread may still queue on the
// mutex, and callbacks using an independent arbiter remain valid.
thread_local! {
    static ACTIVE_ARBITERS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

fn callback_active(arbiter: &EpochArbiter) -> bool {
    let identity = arbiter as *const EpochArbiter as usize;
    ACTIVE_ARBITERS.with(|active| {
        active
            .try_borrow()
            .map_or(true, |items| items.contains(&identity))
    })
}

struct ActiveCallback {
    identity: usize,
}

impl ActiveCallback {
    fn enter(arbiter: &EpochArbiter) -> Result<Self, Denied> {
        let identity = arbiter as *const EpochArbiter as usize;
        ACTIVE_ARBITERS.with(|active| {
            let mut items = active.try_borrow_mut().map_err(|_| Denied)?;
            if items.contains(&identity) {
                return Err(Denied);
            }
            items.push(identity);
            Ok(Self { identity })
        })
    }
}

impl Drop for ActiveCallback {
    fn drop(&mut self) {
        ACTIVE_ARBITERS.with(|active| {
            active
                .borrow_mut()
                .retain(|identity| *identity != self.identity);
        });
    }
}

impl Default for EpochArbiter {
    fn default() -> Self {
        Self::new()
    }
}

impl EpochArbiter {
    /// Start closed to all operations until external verified policy bootstrap.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                last_epoch: 0,
                phase: Phase::Unavailable,
            }),
        }
    }

    // This function DOES NOT verify durable state or caller identity.
    // Until those are provided by a separate protected broker, it is unsafe
    // to wire this primitive into any production authorization path.
    // No production bootstrap backend exists yet. Prevent downstream crates
    // from passing arbitrary epochs as if they were independently attested.
    #[allow(dead_code)]
    pub(crate) fn accept_externally_committed_epoch(&self, epoch: u64) -> Result<(), Denied> {
        if callback_active(self) {
            return Err(Denied);
        }
        let mut state = self.state.lock().map_err(|_| Denied)?;
        if state.phase != Phase::Unavailable || epoch == 0 || epoch <= state.last_epoch {
            return Err(Denied);
        }
        state.last_epoch = epoch;
        state.phase = Phase::Active;
        Ok(())
    }

    /// Revoke and retain the process-local high-water epoch.
    pub fn revoke(&self) -> Result<(), Denied> {
        if callback_active(self) {
            return Err(Denied);
        }
        let mut state = self.state.lock().map_err(|_| Denied)?;
        if state.phase == Phase::Closed {
            return Err(Denied);
        }
        state.phase = Phase::Unavailable;
        Ok(())
    }

    /// Permanently deny this process-local gate instance.
    pub fn close(&self) -> Result<(), Denied> {
        if callback_active(self) {
            return Err(Denied);
        }
        let mut state = self.state.lock().map_err(|_| Denied)?;
        state.phase = Phase::Closed;
        Ok(())
    }

    // Synchronous operation executes while the epoch lock is held.
    // Its closure MUST operate through a pinned native handle, never reopen
    // an absolute pathname. Cancellation/nonblocking I/O is still unbuilt.
    /// Serialize the entire synchronous closure with epoch changes.
    /// Callers must separately provide trusted OS identity and handle-based I/O.
    pub fn execute<T, E>(
        &self,
        expected_epoch: u64,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, Denied> {
        let _callback_scope = ActiveCallback::enter(self)?;
        let state = self.state.lock().map_err(|_| Denied)?;
        if expected_epoch == 0 || state.phase != Phase::Active || state.last_epoch != expected_epoch
        {
            return Err(Denied);
        }
        Ok(operation())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn recursive_calls_on_same_arbiter_deny_without_deadlocking() {
        let gate = EpochArbiter::new();
        assert_eq!(gate.accept_externally_committed_epoch(1), Ok(()));
        assert_eq!(
            gate.execute(1, || {
                let mut nested_operation_ran = false;
                assert_eq!(
                    gate.execute(1, || {
                        nested_operation_ran = true;
                        Ok::<_, ()>(())
                    }),
                    Err(Denied),
                );
                assert!(!nested_operation_ran);
                assert_eq!(gate.revoke(), Err(Denied));
                assert_eq!(gate.close(), Err(Denied));
                assert_eq!(gate.accept_externally_committed_epoch(2), Err(Denied));
                Ok::<_, ()>(())
            }),
            Ok(Ok(())),
        );
        assert_eq!(gate.execute(1, || Ok::<_, ()>(42)), Ok(Ok(42)));
        assert_eq!(gate.revoke(), Ok(()));
        assert_eq!(gate.execute(1, || Ok::<_, ()>(42)), Err(Denied));
    }

    #[test]
    fn nested_operations_on_different_arbiters_preserve_independent_authority() {
        let first = EpochArbiter::new();
        let second = EpochArbiter::new();
        assert_eq!(first.accept_externally_committed_epoch(1), Ok(()));
        assert_eq!(second.accept_externally_committed_epoch(7), Ok(()));
        assert_eq!(
            first.execute(1, || second.execute(7, || Ok::<_, ()>(9))),
            Ok(Ok(Ok(9))),
        );
    }

    #[test]
    fn defaults_to_deny_and_rejects_stale_or_equal_epochs() {
        let gate = EpochArbiter::new();
        let mut mutated = false;
        assert_eq!(
            gate.execute(1, || {
                mutated = true;
                Ok::<_, ()>(())
            }),
            Err(Denied)
        );
        assert!(!mutated, "unavailable gate must never invoke operation");
        assert_eq!(gate.accept_externally_committed_epoch(0), Err(Denied));
        assert_eq!(gate.accept_externally_committed_epoch(7), Ok(()));
        assert_eq!(gate.accept_externally_committed_epoch(7), Err(Denied));
        assert_eq!(gate.accept_externally_committed_epoch(6), Err(Denied));
        assert_eq!(gate.execute(6, || Ok::<_, ()>(123)), Err(Denied));
        assert_eq!(gate.execute(7, || Ok::<_, ()>(123)), Ok(Ok(123)));
        assert_eq!(gate.revoke(), Ok(()));
        assert_eq!(gate.accept_externally_committed_epoch(8), Ok(()));
        assert_eq!(gate.execute(7, || Ok::<_, ()>(123)), Err(Denied));
        assert_eq!(gate.execute(8, || Ok::<_, ()>(123)), Ok(Ok(123)));
    }
    #[test]
    fn active_epoch_cannot_be_replaced_without_explicit_revoke() {
        let gate = EpochArbiter::new();
        assert_eq!(gate.accept_externally_committed_epoch(5), Ok(()));
        assert_eq!(gate.accept_externally_committed_epoch(6), Err(Denied));
        assert_eq!(gate.execute(5, || Ok::<_, ()>(5)), Ok(Ok(5)));
        assert_eq!(gate.execute(6, || Ok::<_, ()>(6)), Err(Denied));
        assert_eq!(gate.revoke(), Ok(()));
        assert_eq!(gate.accept_externally_committed_epoch(6), Ok(()));
        assert_eq!(gate.execute(5, || Ok::<_, ()>(5)), Err(Denied));
        assert_eq!(gate.execute(6, || Ok::<_, ()>(6)), Ok(Ok(6)));
    }

    #[test]
    fn revoke_keeps_high_water_and_close_is_irreversible() {
        let gate = EpochArbiter::new();
        assert_eq!(gate.accept_externally_committed_epoch(5), Ok(()));
        assert_eq!(gate.revoke(), Ok(()));
        assert_eq!(gate.execute(5, || Ok::<_, ()>(1)), Err(Denied));
        assert_eq!(gate.accept_externally_committed_epoch(5), Err(Denied));
        assert_eq!(gate.accept_externally_committed_epoch(6), Ok(()));
        assert_eq!(
            gate.execute(6, || Err::<(), _>("io-failure")),
            Ok(Err("io-failure"))
        );
        assert_eq!(gate.close(), Ok(()));
        assert_eq!(gate.execute(6, || Ok::<_, ()>(1)), Err(Denied));
        assert_eq!(gate.accept_externally_committed_epoch(7), Err(Denied));
        assert_eq!(gate.revoke(), Err(Denied));
    }

    #[test]
    fn operation_linearizes_before_concurrent_revoke() {
        let gate = Arc::new(EpochArbiter::new());
        assert_eq!(gate.accept_externally_committed_epoch(1), Ok(()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (revoke_tx, revoke_rx) = mpsc::channel();
        thread::scope(|scope| {
            let op_gate = Arc::clone(&gate);
            let operation = scope.spawn(move || {
                op_gate.execute(1, || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok::<_, ()>(1)
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let revoke_gate = Arc::clone(&gate);
            let revoker = scope.spawn(move || {
                revoke_tx.send(()).unwrap();
                revoke_gate.revoke()
            });
            revoke_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            // The operation held the lock before revoke began.
            release_tx.send(()).unwrap();
            assert_eq!(operation.join().unwrap(), Ok(Ok(1)));
            assert_eq!(revoker.join().unwrap(), Ok(()));
        });
        let mut bytes_changed = false;
        assert_eq!(
            gate.execute(1, || {
                bytes_changed = true;
                Ok::<_, ()>(())
            }),
            Err(Denied)
        );
        assert!(!bytes_changed, "no operation after completed revoke");
    }

    #[test]
    fn panic_poison_does_not_regrant_access() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let gate = EpochArbiter::new();
        assert_eq!(gate.accept_externally_committed_epoch(1), Ok(()));
        let panic = catch_unwind(AssertUnwindSafe(|| {
            gate.execute(1, || {
                panic!("simulated operation crash");
                #[allow(unreachable_code)]
                Ok::<_, ()>(())
            })
        }));
        assert!(panic.is_err());
        assert_eq!(gate.execute(1, || Ok::<_, ()>(1)), Err(Denied));
        assert_eq!(gate.accept_externally_committed_epoch(2), Err(Denied));
    }

    #[test]
    fn exhausted_epoch_space_denies_reactivation() {
        let gate = EpochArbiter::new();
        assert_eq!(gate.accept_externally_committed_epoch(u64::MAX), Ok(()));
        assert_eq!(gate.revoke(), Ok(()));
        assert_eq!(
            gate.accept_externally_committed_epoch(u64::MAX),
            Err(Denied)
        );
        assert_eq!(gate.execute(u64::MAX, || Ok::<_, ()>(1)), Err(Denied));
    }

    #[test]
    fn restart_replay_remains_possible_without_external_trusted_storage() {
        // This is a NEGATIVE security proof, not an acceptance of replay safety.
        let previous_process = EpochArbiter::new();
        assert_eq!(
            previous_process.accept_externally_committed_epoch(9),
            Ok(())
        );
        assert_eq!(previous_process.revoke(), Ok(()));
        let new_process = EpochArbiter::new();
        assert_eq!(
            new_process.accept_externally_committed_epoch(1),
            Ok(()),
            "in-memory state CANNOT prove monotonicity across a restart"
        );
        // Production must refuse to start absent independently protected state.
    }
}
