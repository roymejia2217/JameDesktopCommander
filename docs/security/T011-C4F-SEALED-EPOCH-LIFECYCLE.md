# T011-C4f — Sealed process-local epoch lifecycle

**Status:** Experimental Rust hardening only. No protected authority, service,
durable policy store, IPC endpoint or production filesystem migration.
Baseline: protected main `c3bc6879c67b1a0d84d3c498f321a232bb45a3ce`.

## Security flaw fixed inside the experimental core

C4e publicly exposed `EpochArbiter::accept_externally_committed_epoch`,
which let an arbitrary downstream Rust crate activate a gate with a
caller-supplied epoch. C4e also allowed an active epoch 5 to be replaced
directly by epoch 6 without first revoking epoch 5. Once a broker binds
pinned root handles to epochs, this state transition could let a new
epoch reach handles retained from a previous policy.

C4f confines the epoch promotion method to `pub(crate)`. A separate
Rust consumer can construct a denied gate and issue denied operations,
but **cannot rearm it from untrusted input**. This is a compile-time API
guard, not a privilege boundary against code inside the crate or a
malicious actor controlling the binary.

The state machine now requires an explicit revoke between active epochs:

- `Unavailable` → active epoch N: available only from future internal
  trusted bootstrap code, **not yet implemented**.
- Active N → active M: rejected without a prior explicit revoke, including
  when M is higher. Active N remains active after the rejected attempt.
- Active N → unavailable: `revoke()` completes only once all synchronous
  operations holding the mutex have returned.
- Unavailable after revoke → active M: M must be strictly greater than
  the process-local high-water epoch.
- `close()` is terminal; poisoned mutexes deny all subsequent access.

**Important:** this core has no authenticated policy, independent
identity or verified native root handle registry. It does not itself
close or replace handles; a future broker must bind native capabilities
and epoch transactions under the same protected lifecycle.
## Evidence (not security signoff)

- TDD RED: the active→active update was accepted before the fix.
  The new unit regression failed, then passed after the transition guard.
- One external integration test confirms a new external consumer cannot
  execute operations without an unimplemented trusted bootstrap.
- A Rust `compile_fail` documentation test verifies that an external
  crate cannot invoke the former epoch-promotion method.
- The native CI job is changed from `cargo test --lib` to full
  `cargo test --locked`, covering unit, integration and compile-fail
  doctests on pinned Rust 1.91.1 for Windows and Linux.
- Rust local `cargo test` and `cargo clippy --all-targets -D warnings`
  must pass, as must normal JDC CI, CodeQL, governance, native tests and
  unpublished portable acceptance before any merge.

## Explicit remaining blockers

This does **not** prevent config rollback or A→B→A after restart, as the
C4e negative test demonstrates. No independently managed Windows service
SID/ACL, Linux credential-authenticated Unix socket, policy-store durable
anti-replay proof, authenticated peer identity, native capability-to-epoch
association, cancellation, bounded operation time or zero-unauthorized-
byte-mutation evidence exists. Any future implementation of the internal
bootstrap path must be reviewed along with its trust domain, OS identities
and actual durable policy commit before allowing it to activate a gate.

All MCP filesystem handlers retain their existing behavior. This increment
does not authorize runtime deployment or mark T011 production-ready.
