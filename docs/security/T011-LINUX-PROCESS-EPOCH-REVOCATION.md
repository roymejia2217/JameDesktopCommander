# T011-C4 — Process-local sticky epoch revocation (NON-RELEASE)

**Scope:** issue #139, isolated Linux native authority-service component. This is a **generation observation**, not a policy issuer, a grant, a reader/writer lock, an IPC endpoint, an administrator publisher or a durable counter. `native/authority-service/src/main.rs` intentionally still returns `E_POLICY_UNAVAILABLE`.

## Primitive

`PolicyEpochMonitor::from_current_os_attested()` obtains one genuine, bounded SQLite policy snapshot via the already implemented Linux kernel-pinned root-admin directory and file, independently checks the root-owned epoch/digest witness before and after the read, and stores only that verified epoch and SHA-256 digest. No user path, rootRef, arbitrary policy text or synthetic identifier enters the public constructor.

A monitored process calls `revalidate_current(&mut self)` to re-observe actual OS-controlled state. Repeated matching observations are allowed. A changed epoch (forward or rollback), changed digest at equal epoch, malformed/missing policy or witness, or any OS/SQLite read error **permanently poisons the instance**. Returning a formerly accepted matching pair after a mismatch never reactivates the poisoned monitor. No method allows a caller to mutate the expected generation or clear the poison bit. Rust `&mut` serializes mutation of a monitor instance, but does NOT synchronize filesystem operations or make it a revocable capability.

## Actual test contracts

The existing mandatory Linux T011 acceptance also runs one disposable process under the *actual* `jdc-authority` kernel account with `NoNewPrivs: 1`. An event-driven Bash coprocess sends three fixed `check` messages over stdin, with explicit readiness/response acknowledgments and bounded event waits. Root independently replaces the policy with epoch 2 between the stable first read and the second read, then restores the old matching epoch-1 SQLite image and witness before the third read. The service must return `MONITOR_MATCH`, `MONITOR_DENIED`, `MONITOR_DENIED` from that *same process instance*. The probe is a CI-only compiled example with no IPC grants or filesystem operation APIs; the fixture does not simulate a crash-safe publisher. A restored pair can still be accepted by a newly started monitor (the negative whole-state rollback tier remains unchanged).

The Linux-only Rust suite covers invalid initial epoch/digest, multiple stable positive observations, a real representative matrix of forward epoch change, rollback, same-epoch digest replacement, mismatch with stale digest and malformed data, irreversible poison after restoring the old pair, sticky poison after a failed observation, and fail-closed refusal to construct from the ordinary non-service identity. All OS-root actual acceptance remains in the mandatory Linux native job and independent prior T011 acceptance script. The Windows build cannot execute this `#[cfg(target_os = "linux")]` module; its regression and Node source contracts are distinct evidence.

## Unresolved mandatory release gates

This **does not** create an actual runtime session or link into authenticated C4d dispatch. There is no process-lifetime owner of this monitor yet, so callers must not assume it protects live operations. A future broker must enforce ownership of exactly one generation monitor, retain an OS-pinned root and durable independently witnessed replay ledger, and check policy/revocation under a carefully designed lock or linearization point **throughout** in-flight operations. A new monitor may still be created after process restart when an attacker has rolled back *both* local policy and witness; this tier cannot detect complete administrator/offline state rollback. A trusted updater must implement forward-only durable publication, explicit recovery and crash injection before reissuing any grants. #124 N-API and #148 object/hardlink isolation remain separate P0 gates.

**Release status:** `releaseEligible:false`; keep #139 OPEN and #170 DRAFT. No existing service installation, executable entry point, MCP handler or production runtime is modified.
