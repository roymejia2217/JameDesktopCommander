# T011-C4h — Coherent policy/replay SQLite transaction (test-only research)

**Status:** Experimental RED→GREEN test fixture. **NON-RELEASE**. Issue #139 remains P0/open; #124 and #148 remain independent P0. This note neither approves a single-database production design nor makes an issuer available.

## Engineering question

Can one existing, version-pinned `rusqlite` SQLite transaction verify the exact bounded policy bytes, epoch and digest and consume a canonical UUIDv4 replay identifier before committing, so a locally modified policy epoch and replay claim are not observed as two independent commits?

The previously isolated `PolicyBytesStore` (v2) and `ReplayClaimLedger` (v1) use separate, exact schemas and do not implement that shared commit boundary. Their public policy-read API is still pathname-based offline data, not proof of trusted physical SQLite custody.

## Test-only implementation

`native/authority-store/src/coherent_transaction_proof.rs` is included strictly under `#[cfg(test)]`; **none of its constructors, connection-open helpers, transactions or test administrator writes compile in the runtime library**.

The disposable v3 research schema contains exactly two tables: one strict policy row storing epoch, SHA-256 digest and up to 65,536 bytes, and a composite-unique replay table storing 8-byte epochs and 16-byte UUIDs. It uses SQLite's existing `BEGIN IMMEDIATE` semantics through `rusqlite::TransactionBehavior::Immediate`, a bounded read of actual policy bytes, explicit schema and journal checks, `synchronous=EXTRA`, and a per-epoch 1,024-request limit. There is no migration or automatic production enrollment.

Only when a caller-supplied epoch and digest match the same-transaction policy row **and** the policy's actual SHA-256, and the UUID satisfies version 4 and RFC variant bits, does the SQLite transaction attempt a unique replay insert. A rejected or concurrent losing request does not commit an insert. The witness arguments are **untrusted test inputs**; matching them is not service authorization.

## Actual acceptance and negative proof

1. Matching policy epoch+digest and valid ID: one commit, replay DENIED on reuse. Wrong epoch/digest/malformed UUID: DENY without additional replay rows.
2. Simulated administrator epoch promotion from 7 to 8: stale epoch 7 denied with an already-open connection; a separately supplied 8/digest accepts one claim.
3. Two connections racing to insert the same UUID: exactly one winner and durable duplicate DENY.
4. Schema modification between opening and claiming: DENY before committing.
5. **Explicit negative proof:** restoring an older full SQLite image revives a consumed ID when the matching witness is also replayed or absent. Even a single ACID database **does not** resist whole-state rollback.

## Unresolved production gates

- A separately authenticated administrator/updater owns the durable policy and high-water witness; the MCP caller and broker reader cannot alter either.
- Standard SQLite VFS must be evaluated in a protected, OS-verified state directory for primary file, journal/sidecars, links and ancestor swaps. A Rust `File` or `/proc/self/fd` string does not create descriptor-pinned SQLite custody.
- A separate OS-owned immutable/monotonic witness is needed for the selected local threat profile. Restoring BOTH DB and local witness remains outside that profile without stronger hardware/remote evidence.
- Atomic ordering of policy revocation, active grants, replay claim and native file I/O has not been proved. A committed replay claim before a failed I/O must not authorize a retry under a changed namespace.
- Linux systemd service+administrator peer separation, Windows SCM/service SID/DACL and actual protected publisher, crash injection, thread cancellation and recovery are absent from this test-only proof.
- #124 FFI/N-API and #148 concurrent hardlink object custody remain completely independent; the normal service continues `E_POLICY_UNAVAILABLE`.

**Release verdict:** `releaseEligible:false`. Do not merge as authorization, enable any public operation, alter production services, weaken CI or claim protected state provenance from this module.
