# ADR-T011-001 — Policy provenance, durable state and anti-rollback authority

- **Status:** Proposed — architecture review required; NON-RELEASE
- **Date:** 2026-10-26
- **Scope:** JameDesktopCommander T011, issues #139, #124 and #148
- **Review baseline:** PR #170 `57683a907cab9429aa5d5b0ef6ad832bb0011ba4`
- **Decision owner:** JDC architecture / security review
- **Production verdict:** `releaseEligible:false`

## Context and concrete evidence

The experimental `native/authority-store` already uses `rusqlite =0.37.0`
with SQLite's existing transactions and a single-row `PolicySnapshot {epoch, digest}`.
`EpochStore::open_existing(path)` still reopens a pathname and is expressly
not an authority. The service-side Windows proof independently reads one
administrator-owned 40-byte `PolicyAnchorV1` Registry value (epoch + SHA-256
digest) under an SCM identity. Linux has an experimental descriptor-bound
state-directory acquisition. The store, genuine policy bytes, witness and
authenticated updater are **not** integrated. The Windows proof uses synthetic
digest bytes. No client can receive a capability from these proofs.

Distinguish transaction atomicity, durable storage, authentic policy provenance,
rollback of one store, rollback of both stores, runtime authorization and
containment of hard-linked objects. An additional database or policy evaluator
does not make these properties interchangeable.

## Decision — minimal professional substrate (proposed, not deployed)

1. **Keep SQLite + rusqlite** for ACID transactions, concurrency and a narrowly
   scoped durable policy store. Use vendor-supported SQLite journal/sync
   semantics, not a custom transaction or cryptographic database.
   Existing `journal_mode=DELETE` and `synchronous=EXTRA` constraints are
   experimental; verify OS power-loss guarantees and sidecar custody on both
   target platforms before declaring them production guarantees.
2. **Anchor policy approval in a separate OS security principal.** The
   unprivileged MCP/Node client is never the authority; the broker is a
   constrained reader/executor; a distinct administrator-controlled updater
   alone may approve a new policy and advance the high-water witness. The
   broker must not mutate either the witness or the trusted approved policy.
   ACL/DACL ownership and effective ancestor permissions must be proven on
   real operating-system objects. A single process running with all
   privileges is not adequate separation.
3. **Retain the Windows proof's atomic Registry value** as the candidate
   witness for the *local, less-privileged-attacker* profile, with fixed path,
   exact typed value and verified owner/protected DACL. On Linux use a
   root-/administrator-controlled state witness under verified safe ancestors
   with a separate non-root reader identity. The Linux witness's lifecycle,
   atomic replacement, fsync and protected directory acquisition are **not
   implemented or accepted**. The Windows test fixture is NOT an installer.
4. **Hash exactly the approved effective policy bytes**, using a standard
   SHA-256 implementation. The protocol must specify a versioned byte encoding,
   maximum size, duplicate-key/unknown-field rejection, deterministic
   interpretation and parser compatibility. Do not invent a canonicalizer:
   either define an approved exact-byte envelope whose bytes are retained
   unchanged, or select an audited, interoperable canonical representation
   such as RFC 8785 and validate its library/license. The digest in a DB row
   is data, not proof that the approver accepted those policy bytes. Never
   authorize from an epoch+digest without custody, provenance and actual-byte
   verification.
5. **Compare one authenticated DB snapshot to the independently observed
   witness exactly** before any authorization: epoch AND digest must match.
   Missing/unreadable/invalid witness or DB, differing digest at same epoch,
   lower/higher epoch or unverified origin => DENY. Matching alone is not
   sufficient: the service identity, signed/provisioned policy, revocation,
   IPC peer and handle-bound operation must independently pass. Never fall
   back to `realpath() -> fs.*` after a native-control failure.
6. **Do not introduce TUF/OPA/TPM/SQLCipher/immudb as a mandatory runtime
   dependency today.** TUF is the preferred *conditional* standard for
   remotely distributed, versioned signed policy bundles; it does not
   authorize local process identity or resist a full-device rollback alone.
   OPA is a *conditional* decision engine for genuinely complex declarative
   policies, not a trust anchor. TPM 2.0/external witnesses are profile-based
   enhancements only after requirements and hardware availability are
   established. SQLCipher is for confidentiality, not rollback resistance.
7. **Preserve deny-only service behavior** and keep the PR in DRAFT until
   a complete vertical integration passes adversarial Windows/Linux testing.

## Technology selection matrix

| Component | Appropriate guarantee | License / maturity evidence | Cost and decision |
| --- | --- | --- | --- |
| SQLite / rusqlite | Transaction, durability under documented filesystem/sync assumptions; serialized writer | SQLite public domain, mature cross-platform core; crate already pinned | Embedded, no additional daemon. **KEEP**. Not an authenticity or rollback proof. |
| Windows Registry + Win32 / SCM | OS principal ACLs, local separate witness | Standard Windows APIs; concrete experimental SCM acceptance exists | Small local footprint. **CANDIDATE Windows local witness**; no machine-image rollback protection. |
| Linux root-owned storage + systemd | OS identity separation and root-controlled witness/credential delivery | Standard Linux/systemd controls and documentation | No mandatory extra daemon beyond OS. **CANDIDATE Linux witness**, acceptance still missing. |
| The Update Framework (TUF); Rust `tough` | Signed remote distribution; delegation, metadata versions, mix-and-match/freeze/rollback checking | TUF specification; `tough` dual MIT/Apache-2.0; library selection/version/security review pending | Additional keys, signing pipeline and release process. **DEFER to remote-policy profile**. |
| Open Policy Agent (OPA) | Declarative policy evaluation/bundle management | Apache-2.0; mature ecosystem, official APIs/Wasm | Runtime/build complexity and memory/CPU **not benchmarked in JDC**. **DEFER** pending measurable policy complexity. |
| TPM 2.0 / OS CNG | Hardware-backed cryptographic storage and some protected monotonic-state designs | Vendor/TCG TPM ecosystem; `tpm2-tss` APIs are established | Hardware/provider support not verified; counter endurance/provisioning/backup/recovery TBD. **OPTIONAL hardened profile**. |
| External independent witness | Detect concurrent rollback of DB and OS-held witness when external trust remains available | Requires trusted operator/provider and authenticated protocol | Network, outage and trust-management overhead. **OPTIONAL high-assurance profile**. |
| SQLCipher | Database confidentiality at rest | Community BSD-style conditions; inspect artifact licenses before adoption | Crypto/key-management cost. **NOT REQUIRED** for antirollback. |
| immudb | Verifiable database history/checkpoints | Current upstream project uses BSL 1.1, not blanket Apache-2.0 | Separate engine/runtime and license review burden. **REJECT** for minimum local deployment. |

Specific published CVEs, advisory triage, exact versions for any newly selected
dependency, benchmarked RSS/latency/CPU, and GPL distribution compatibility
require dedicated evidence at procurement/integration time. This ADR makes
**no** unverified claim that any candidate has zero vulnerabilities or fixed
resource usage.

## Threat model and assurance boundary

- **Attacker A:** unprivileged MCP caller; cannot forge OS-authenticated IPC
  identity or obtain writable trusted storage by supplying paths/tokens.
- **Attacker B:** less-privileged process with mutable workspace/files; can
  replay, edit, rename or hard-link its own files. Only independently owned,
  OS-enforced custody can prevent changing protected files and anchors.
- **Attacker C:** compromised reader service principal. It must lack witness
  update rights; avoid policy-write privileges and privileged executable
  handlers. If it owns the effective writable DB, exact DB+witness equality
  detects an arbitrary forged row absent witness control, **but does not
  establish file custody or policy authenticity**.
- **Attacker D:** administrator, trusted updater, kernel, firmware or offline
  image/Registry hive restoration. OS ACLs alone do not protect against D.
  Restoring BOTH SQLite and the local witness to an older consistent state is
  **not detectable by the local equality check**. Hardware-backed monotonic
  state or a surviving external witness is needed for a stronger claim.
- **Separate issue #148:** root confinement does not imply outside-object
  byte isolation via hardlinks. Require actual native sentinel tests; an
  equal epoch+digest does not solve object aliasing.
- **Separate issue #124:** no native addon becomes safe solely by satisfying
  this storage decision; independently resolve N-API lifetime/aliasing.

### Assurance tiers (avoid overstating protections)

- **Local-separated-authority** (target baseline): protects against A/B
  within demonstrated host/principal/ACL assumptions; denies mismatched DB
  and witness; does not claim D resistance.
- **Hardware/remote antirollback** (optional): required for documented
  offline whole-system-rollback adversaries; availability, migration,
  lifecycle and recovery policies must be verified before offering it.

## Proposed protocol, not an implemented transaction

**Provisioning:** a separately authenticated administrator/updater validates
the trusted installation and protected ancestry, creates a versioned approved
policy (bounded bytes), persists a durable SQLite policy snapshot, and
publishes the matching OS witness. Admission starts DENY until both are
provably coherent. No service-origin self-enrollment or default-grant path.

**Update ordering:** serialize updaters via an OS-enforced administrative lock
and explicit expected previous epoch; authenticate origin, validate policy
and enforce `next > previous`. Stage/commit the new policy and DB using
SQLite's supported durable mechanisms, then advance the independently
owned witness. **These two durable writes are NOT one atomic transaction.**
The witness advancement is the *candidate* activation linearization point,
subject to validated persistence, reader synchronization and OS semantics.
On a crash between writes, readers observe mismatch and DENY. It is never
correct to use whichever of the two values is newer as an automatic grant.

**Runtime:** acquire both sources through independently verified OS authority,
read a consistent policy and witness, compare both fields, bind admission to
the verified actual bytes and to a revocable in-process generation. An epoch
change must invalidate active grants; any in-flight operation needs an
explicitly defined linearization/locking rule. Merely checking once at
process startup is insufficient. A stale capability and stale IPC session
must never continue using an old authorization after committed revocation.

**Recovery:** intentional fail-closed degradation until an independently
authenticated updater reconciles recorded state. Allowed actions must be
formally bounded (e.g., finish a fully authenticated forward-only prepared
update); **never** silently lower witness epoch, copy an old DB or mint a
matching digest. Record causal evidence without logging policy secrets. A
crash matrix must exercise before/after DB sync, witness write, witness
flush, session invalidation, restart and concurrent readers. Pending-recovery
data cannot itself authorize execution. Whether forward recovery requires
an auxiliary durable intent journal is deferred until a tested state machine
exists; do not author a homemade distributed transaction manager.

## Gate: SQLite physical custody and VFS design

SQLite's supported `sqlite3_open_v2` uses a filename and optional VFS name;
`SQLITE_OPEN_NOFOLLOW` prohibits opening a symlink as the DB filename but
alone does NOT establish trusted ancestors or protect journal sidecars,
hardlinks, races or principal isolation. SQLite's VFS owns underlying OS
opens, locks and journal files. Do **not** claim that passing an arbitrary
`/proc/self/fd` string, retained directory FD, Rust `File`, or copied
bytes to existing `rusqlite::Connection::open*` proves handle custody.

Before any integration, inspect available supported SQLite VFS options and
write a scoped, cross-platform feasibility/acceptance specification.
Preference order: (1) a truly protected installation-owned state directory,
dedicated reader/writer identities, safe ancestor and sidecar contracts and
standard SQLite VFS with tested race resistance; (2) only if (1) cannot
satisfy the threat model, a professionally maintained supported VFS/driver
with a precisely documented handle-lifecycle contract. Do not hand-roll
a VFS for convenience. On unsatisfied custody requirements, DENY.

## Required RED -> GREEN evidence and release gates

1. Real approved policy bytes and versioned schema; negative tests for
   semantic substitution, duplicate keys, parser drift, altered policy,
   forged publisher and same-epoch digest.
2. Real Windows/NTFS SCM key+DB ownership; Linux/systemd separate principals;
   positive controls that demonstrate the attacker CAN manipulate its own
   data, and negative controls protecting the trusted assets.
3. DB path and parent/sidecar swap races, symlinks/reparse points, hardlinks,
   file replacement after open and interrupted SQLite commits.
4. Rollback old DB vs latest witness; mismatched digest; witness rollback;
   both locally restored (explicitly documented unprotected case).
5. Crash injection at every persistence edge; authenticated forward recovery,
   no implicit downgrade; two competing administrative updates.
6. Revocation across IPC sessions, reconnection and service restart; no
   authorize-on-read caching bug; no unchecked fallback to ambient FS calls.
7. Thread lifetime/FFI under Miri+CodeQL and concrete native Windows/Linux
   E2E, covering independently open #124 and #148.
8. Pin chosen dependency versions; license compatibility (including
   GPL/release notices), upstream CVE/advisory scan, benchmarks under 8 GB
   Windows and restricted Linux target, install/uninstall/upgrade/restore
   acceptance and observability. Run official release CI on **exact HEAD**.

**Current acceptance:** documentation-only architectural decision proposed.
No runtime behavior or security boundary changes. TDD is not applicable to
this documentation-only delta; all implementation requires failing tests
before fixes. #124/#139/#148 remain P0. Do not merge to `main` or claim
`releaseEligible:true`.

## Primary references (official sources; reviewed 2026-10-26)

- SQLite transactions/WAL: https://www.sqlite.org/wal.html
- SQLite sync semantics: https://www.sqlite.org/pragma.html
- SQLite file open contract: https://sqlite.org/c3ref/open.html
- SQLite VFS layer: https://www.sqlite.org/vfs.html
- SQLite licensing: https://www.sqlite.org/copyright.html
- Microsoft Registry APIs: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-functions
- Microsoft Registry key ACL: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights
- systemd credentials: https://systemd.io/CREDENTIALS/
- TUF specification: https://github.com/theupdateframework/specification/blob/master/tuf-spec.md
- TUF Rust `tough`: https://github.com/awslabs/tough
- OPA integration and bundles: https://www.openpolicyagent.org/docs/integration
- OPA Wasm constraints: https://www.openpolicyagent.org/docs/wasm
- TPM2 software stack: https://tpm2-tss.readthedocs.io/en/latest/
- SQLCipher upstream license: https://github.com/sqlcipher/sqlcipher/blob/master/LICENSE.txt
- immudb upstream license: https://github.com/codenotary/immudb/blob/master/LICENSE
