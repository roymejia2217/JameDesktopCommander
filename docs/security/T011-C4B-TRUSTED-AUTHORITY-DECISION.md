# T011-C4b — Trusted filesystem policy authority: security decision and gate

**Status:** Architectural gate proposed for review; **no trusted authority has
been implemented or deployed**. Baseline: protected `main`
`f2946705949854ebd55b3cfa7a1594e31f5fc36f` (T011-C4a postmerge accepted).

## Security decision: config metadata is never an authority

The current `allowedDirectories`, candidate revision SHA-256 and opt-in
`__jdcFilesystemPolicyGeneration` live in the same modifiable JSON file.
An editor able to replace that file can replace the counter, fingerprint and
policy together, including a complete replay A → B → A. Any extra counter,
checksum, HMAC with a key stored under the same principal, SQLite table, lock
file or watcher **in that same trust domain** cannot establish rollback
resistance. The passing unmanaged-ABA regression explicitly demonstrates
this limitation. Do not present such techniques as remediation.

This is not a cryptographic hash collision: the historical authorized values
are valid *old values*. An attacker replays them. No content-only comparison
can distinguish that history without separate trusted state.

A genuinely authoritative implementation requires a security principal and
durable state not writable/replayable by the configuration editor. Acceptable
candidate architectures must *prove*, not assume:

1. **Trust separation.** A distinct protected authority process or hardware/
   remote trust boundary, with a verified caller identity and ACL/capability
   enforcement. On Windows, authenticate named-pipe clients and protect
   service state with an independently managed OS identity. On Linux, use
   authenticated Unix-domain socket credentials and independently protected
   storage/identity, or an equivalent established platform mechanism.
   Running both halves as the same unrestricted user is not separation.
2. **Linearizable authority.** A persistent increasing epoch, durable across
   restart/crash, serialized with policy replacement. A stale, forged,
   truncated, missing, equal-epoch-but-different-policy or replayed policy is
   rejected. Failure to contact the authority denies access, never reverts
   to `validatePath()` or cached unrestricted behavior.
3. **Authorization and operation within the boundary.** The authority must
   open/retain roots securely and operate through anchored native handles.
   Returning pathname approvals or raw replayable authorization claims for
   Node to reopen is forbidden. Namespace replacement, symlink and junction
   changes must not escape the opened root.
4. **Revocation semantics.** A policy update has a well-defined
   linearization point: operations committed before it may complete according
   to an explicitly tested protocol; new or uncommitted operations after it
   must be denied or cancelled. Authorization and file operations must be
   bound to the same epoch while the authority controls their lifecycle.
   Node watchers, a local JSON SHA or closure around asynchronous JavaScript
   callbacks are not a revocation protocol.
5. **Platform, resource and lifecycle constraints.** Support Windows x64
   and Linux x64, Node >=22.19, headless operation, bounded memory and I/O,
   cancellation and shutdown, native ABI compatibility, deterministic failure
   reporting, and recovery without implicit regrant. No additional service,
   installed runtime, credentials or external provider may be introduced
   without a separately reviewed deployment and acceptance gate.

## Enforce the boundary while unresolved

`test/test-t011-authority-isolation.js` uses the maintained TypeScript
parser to inspect production `src` modules. It fails if a production caller
references `RootCapability`, `RestrictedCapabilityPolicy`, the candidate
snapshot/cooperative setter invocation, or the unpublished native addon.
The three *existing definition modules* are exempt solely because they
define these non-authorizing helpers; their call sites are not exempt.
Twelve self-checks detect direct and computed access, extracted method
references, destructuring, import aliases, native imports, and attempts
to import the C4c experimental authority operation data contract.
The existing `npm run test:unit` path runs the gate on the minimum
supported Node version.

This guard prevents *obvious accidental wiring*, not arbitrary reflection,
obfuscated dynamic imports, compromised dependencies or hostile processes.
It must never be cited as runtime confinement or as protection against a
malicious local administrator. Only a dedicated, approved integration PR
may update its exemptions, after authority proofs and independent review.

## Acceptance matrix before any production migration

- Replay tests: A→B→A from unmanaged writer, complete valid config rollback,
  forged matching fingerprint+epoch, stale concurrent process, crash/restart,
  restart after partial policy write, unavailable trusted store, bad identity
  and cross-user requests; assert **zero unauthorized byte mutations**.
- Native identity tests: root path rename and replacement; intermediate and
  terminal symlink/junction swaps while requests execute; hardlinks, Windows
  reparse/device names, path casing, Unicode and volume-boundary behavior.
  On Windows, distinguish actual successful swaps from rename failures due
  to opened handles; neither counts as universal proof by itself.
- Transaction tests: simultaneous revoke/read/write, partial write,
  cancellation, timeout, shutdown, blocked native calls and failed close.
  A successful operation must be tied to a specifically observed epoch,
  without allowing Node pathname reopen after authorization.
- Full call-graph migration: text, binary, DOCX, PDF, Excel, images, edit,
  list, create, move, search, file info, UI workspaces and indirect format
  handlers. Account separately for terminal/process tools whose privileges
  are not constrained by the filesystem tool policy.
- Supply chain and distribution: pinned/provenance-checked Rust dependencies,
  license and advisory audit, signed/versioned native transport package,
  Windows/Linux ABI tests, host-path boundary, protected-branch controls,
  original ZIP/TAR independent per-file audit, real MCP acceptance and
  unchanged public tool schemas. Any incomplete platform remains blocked.

## Explicit non-goals of this increment

This decision + source isolation guard does **not** provide a broker,
monotonic storage, privileged identity, IPC authentication, token issuer,
revocation implementation or proof of TOCTOU elimination. No new production
filesystem permission is granted. It imposes a release gate rather than
adding misleading partial-security functionality.

T011-C4b implementation remains **OPEN** after this architecture gate.
T011-C5+ handler migration, T011-D adversarial real-host concurrency,
T011-E packaging/operational acceptance and production TOCTOU are all OPEN.
Do not enable `releaseEligible`, publish, install, or alter the active
gateway/tunnel/service as part of this review slice.
