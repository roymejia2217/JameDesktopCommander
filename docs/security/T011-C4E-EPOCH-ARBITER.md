# T011-C4e — Isolated epoch serialization feasibility

**Status:** Experimental Rust sequencing library; NOT a trusted filesystem
policy authority, installed broker, release gate completion, or TOCTOU fix.
Baseline protected main: `44eaa324237298b40b1a4ce1d195a655c44ad545`.

## Boundary: a separate crate, not Node authorization

`native/authority-core` is a separate unpublished Rust library with no
third-party dependencies and its own Cargo.lock. Nothing in the MCP runtime
or `native/capability-probe` imports/links this crate, and it does not
expose N-API bindings, IPC sockets, privileged identity, credentials or
file operations. The TypeScript source-isolation gate rejects references
to `authority-core` from productive `src` files.

A data frame, `rootRef`, epoch string, `allowedDirectories` setting
or process-local mutex must NEVER be interpreted as authenticated policy.
The yet-unimplemented broker must verify peer OS identity, independently
protect persistent policy state, and own anchored native root handles.
A service running under the same unrestricted principal as the config
editor would NOT satisfy this trust boundary.

## Precisely tested in-memory ordering semantics

- A new gate starts unavailable; an operation callback cannot execute.
- `accept_externally_committed_epoch` only accepts positive, strictly
  increasing unsigned 64-bit epochs inside the current process. This
  method **does not authenticate or persist** the supplied value.
- A synchronous operation with a matching active epoch executes while
  the mutex remains held. Therefore any revocation or epoch replacement
  linearizes after that operation returns. Stale requests never execute.
- `revoke` makes the gate unavailable while retaining its in-memory
  high-water mark. Reactivation requires a strictly greater epoch.
- `close` permanently denies the instance. A panic poisoning the mutex
  also denies future operation/reconfiguration; there is no fallback.
- A caller-supplied I/O error is distinguishable from an epoch denial,
  but partial I/O may already have occurred. The mutex **does not roll
  back bytes** or make an I/O operation atomic.
## Deliberate negative proof: restart replay remains possible

The test named `restart_replay_remains_possible_without_external_trusted_storage`
demonstrates that, after epoch 9 is observed and revoked in one instance,
a fresh in-memory instance accepts epoch 1. This is a **known failing
security property** and an explicit release blocker, even though the
negative demonstration test itself passes. No local counter, config hash,
cooperative writer or unprotected database can establish monotonicity
against an editor who can replay both policy and state.

The test for `u64::MAX` also proves that exhaustion denies new epochs;
the eventual persistent broker must implement a defined fail-closed
recovery or terminal failure, not wrap the counter.

## Remaining authoritative implementation and acceptance

1. Select and document protected Windows service identity and state ACLs,
   and Linux dedicated service identity/socket credentials/storage
   ownership, with independent cross-principal adversarial tests.
2. Implement and audit a durable, non-replayable policy/epoch transaction
   outside the configuration editor's trust domain. Refuse startup if it
   is missing, corrupt, inaccessible, stale or rolled back.
3. Bind each `rootRef` to a verified caller identity, durable epoch,
   policy roots and securely opened native OS directory handles.
4. Replace synchronous closure-based access with bounded, cancellable
   native operations coordinated against revocation. Long-running
   operations can delay the present mutex indefinitely; this implementation
   does not provide latency or cancellation guarantees.
5. Prove concurrent revoke/operation commit ordering, crash and restart,
   request replay, namespace swaps, link attacks and **zero unauthorized
   byte mutations** across both operating systems.
6. Keep all existing MCP tools on their current path until a separate
   audited migration and deployment gate explicitly authorizes switching.
   No `releaseEligible` flag, installed service, tunnel or public tool
   schema change belongs in this increment.

## Test execution

`cargo test --locked --manifest-path native/authority-core/Cargo.toml`
runs six native tests (including the negative restart replay proof).
CI runs them independently on Windows and Linux with the pinned
Rust toolchain alongside, but not inside, the existing capability probe.
The `test/test-t011-authority-isolation.js` guard exercises an extra
forbidden import fixture. Postmerge checks must pass before integration.
