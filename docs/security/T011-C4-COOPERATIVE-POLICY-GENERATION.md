# T011-C4a — Opt-in cooperative filesystem policy generation

**Status:** Experimental opt-in policy persistence; **NOT** an authorization
capability or production sandbox. Baseline protected main:
`c0608cbb50aa1aa8cca242d3fead1ef105c16034` (T011-C3 accepted).

## Integration boundary and regression repair

The initial T011-C4a revision mistakenly stamped policy metadata from the
generic `ConfigManager.performConfigMutation()` path, thereby causing
`Filesystem policy generation unavailable` errors in unrelated legacy
configuration writes and their teardown operations. Required CI reported
12 preexisting tests failing, despite the new focused tests passing.
**That integration is explicitly rejected.**

The repaired protocol is opt-in: only
`ConfigManager.setFilesystemPolicyCooperatively(allowedDirectories)`
calls `performConfigMutation(mutate, true)`. The latter performs a
policy-before snapshot and calls `stampCooperativePolicyMutation()`
**inside the existing interprocess config lock, before the atomic rename**.
Ordinary `setValue`, `updateValue`, their nonblocking counterparts,
`updateConfig`, `resetConfig`, watcher reloads and background persistence
preserve their historic behavior and never stamp automatically.
`resetConfig()` may legitimately remove experimental stamps; this is
not a security recovery transaction.

The opt-in policy setter validates its candidate input, copies the provided
array and uses the existing serial write queue. It is NOT used by any live MCP
filesystem handler or exposed as an MCP tool. It is not suitable as an
authorization endpoint: unmanaged writers can still bypass the protocol.

Two optional internal config JSON fields are committed on initial
**explicit enrollment**, even if the supplied allowlist is identical to the
legacy on-disk value. The initial generation is 1; repeated unchanged opted-in
writes do not increment it. This removes an unversioned enrollment edge
case, but does not provide rollback resistance.

The fields are:

- `__jdcFilesystemPolicyGeneration`: positive safe integer incremented
  once per opt-in change, including A → B → A, refusing overflow;
- `__jdcFilesystemPolicyFingerprint`: SHA-256 of the raw persisted
  allowlist presence/content, distinguishing absent from explicit `[]`.

Older configs without either marker produce `cooperativeGeneration: null`.
For configs carrying both markers, the non-authorizing candidate parser
rejects malformed/incomplete fields and a fingerprint that does not match
the observed allowlist. Only opt-in writers advance the counter. Changes
to unrelated settings via legacy APIs leave the markers untouched.
If a normal legacy writer changes the allowlist after a stamped policy,
the candidate is denied **while the bytes no longer match** the old
fingerprint, while existing production configuration writes succeed.
**Critical known gap:** an unmanaged A → B → A sequence can restore the
original allowlist and make the stale fingerprint/generation appear valid
again, without any generation increment. A new regression test explicitly
demonstrates this counterexample. The candidate MUST NOT grant filesystem
permissions even if it currently appears internally consistent.

The general-purpose configuration setters explicitly reject attempts to
write the reserved metadata field names. The native restricted capability
manager is not connected to this candidate. The existing
`getAllowedDirectoriesForFilesystem()` and all authorized filesystem
request behavior are unchanged. This is a migration/test harness boundary.

## Mandatory regression gates

The native and portable Windows/Linux tests, all existing CI tests and
the specific `test-filesystem-policy-generation.js` suite must pass on
Node 22.19 and supported platforms. Test evidence must include:

- first opt-in enrollment of an unchanged legacy unrestricted allowlist
  stamps generation 1, repeated no-op opt-in preserves 1;
- Opt-in A → B → A with distinct 1, 2, 3 generations despite repeat digest;
- two cooperating ConfigManager instances serializing opt-in changes;
- ordinary/unrelated writes do not advance or overwrite the metadata;
- opt-in policy arrays are copied, and a generic in-place allowlist change
  taints the candidate but leaves normal writes functional;
- explicit opt-in unrestricted policy resets generation consistently;
- ordinary `resetConfig()` remains backward compatible and un-stamped;
- manually modified allowlist fails candidate and opt-in mutation, while
  legacy unrelated writes continue to work without repairing the stamp;
- all five generic setters reject reserved metadata injection;
- max-safe-integer overflow, incomplete metadata, and malformed policy
  remain denied through the experimental candidate boundary;
- restoration of legacy config during unrelated test teardown produces
  no unhandled generation exceptions;
- a mismatched legacy write remains denied, while an unmanaged A → B → A
  restores the old digest and generation (documented proof of insecurity,
  never considered a passing production authorization gate).

**Red means stop:** The original full CI run on the first revision failed
12 older tests. Do not replace those tests with mocks or weaken their
assertions to claim success. On every new HEAD, require all six PR workflows,
then independent audit of original native and portable ZIP/TAR artifacts
from Windows and Linux before any squash merge. Repeat checks postmerge.

## Unresolved security blockers

This cooperative generation is NOT rollback resistant. An external editor
can remove/replace both stamps or replay a valid historical config; no
trusted external monotonically increasing authority is in place. Nor does
this approach make config reads atomic with opening/using directory handles
or prevent filesystem namespace/symlink/junction swaps. The existing
`validatePath()` → pathname reopen TOCTOU remains unmitigated in production.

The digest remains an observed-content identity, not an authorization
revision. The native addon is test-only and synchronous, and the full
file handler call graph and cancellation/streaming are unimplemented.
T011-C4b+, T011-D and T011-E remain release blockers. No production
runtime, service, tunnel, gateway or official release is modified.
`releaseEligible: false` remains required.
