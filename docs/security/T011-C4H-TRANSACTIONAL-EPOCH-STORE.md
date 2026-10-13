# T011-C4h — Isolated SQLite epoch transaction feasibility

**Status:** Non-authorizing experimental backend. No independently protected
storage, service installation, policy trust root, authenticated IPC,
production filesystem handler migration or release acceptance.
Baseline protected main: `841b6e4451fe62ad9be0a5cc64e141a94d3b2482`.

## Engineering decision: maintained SQLite, not a custom journal

The new `native/authority-store` crate uses the maintained `rusqlite`
wrapper with bundled SQLite, pinned dependencies and a committed Cargo.lock.
This avoids an ad hoc crash-recovery log, bespoke write-ahead scheme,
JavaScript lock file or config-hash "replay detection". Rust tests exercise
the real SQLite engine on the developer host; native CI runs with
Rust 1.91.1 on Windows 2025 and Ubuntu 24.04.

Supply-chain license review identified `foldhash 0.1.5` (via
`rusqlite -> hashlink -> hashbrown`), using SPDX `Zlib`. The shared
`cargo-deny` policy now contains an exact-package, exact-version license
exception for only this crate. No blanket Zlib allowance, advisory
exception, unpinned source or lowered license confidence is permitted.
CI must enforce this exception with `cargo-deny 0.20.2`.
Failure blocks integration; no other packages gain licensing permission.

The crate is **NOT linked** to `native/authority-service`, Node MCP,
the native N-API addon or any running JDC service. Its pathname-based
`EpochStore::open_existing` is an **offline test interface only**, never
a trusted permission to open a store. Production must instead use a
separately provisioned, OS-protected state location and pinned storage
handles with verified ownership/ACLs and authenticated administrator
updates. The service executable remains unconditionally deny-only.

## What the tests can demonstrate

- The store does not create a missing database, provision a default
  policy, fall back to JSON or accept a corrupt file.
- The fixture uses one mandatory record keyed by slot 1, strict 8-byte
  big-endian unsigned epoch and 32-byte policy digest. Arbitrary
  64-bit epochs including `u64::MAX` round-trip without signed truncation.
- An exact version-1 schema, SQLite application identifier and
  `user_version=1` are required. Unexpected triggers, tables, schema
  revisions and weakened table constraints cause rejection.
- Existing store connections use rollback-journal `DELETE` mode and
  request SQLite synchronous `EXTRA`. These are SQLite durability
  settings, **not evidence of immunity to physical power loss** on all
  storage controllers or filesystems.
- Every update uses `BEGIN IMMEDIATE`, checks the previous epoch,
  requires a strictly larger new epoch and commits the epoch and digest
  together using parameterized SQL. Failed or racing updates do not
  advance the record.
- Reopening after a completed commit observes the newer epoch, rejects
  an outdated expected epoch and permits only a strictly increasing
  successor. Two concurrent SQLite connections attempting the same
  initial transition yield exactly one successful transaction.
## Deliberate negative security proof: full-store rollback

The test `whole_database_replay_is_still_possible_without_os_protected_custody`
performs an actual adversarial file replacement: commit epoch 1, copy
the database, commit epoch 2, replace the database with the older copy,
reopen, and observe epoch **1** again. The test passes precisely because
this fundamental **vulnerability is still present** when an attacker
controls the database path and its bytes.

SQLite transaction atomicity, synchronous mode, checksums, schema markers
and file signatures held by the same editor principal cannot prove
non-replayability. A privileged store inaccessible to the config editor,
real cross-user ACL and file replacement tests, OS identity checks,
service lifecycle and independently managed update authority are
mandatory before this backend can be trusted.

The SQLite version and schema checks are format guards, not a signature
or security proof; an adversary with write access can forge both and
substitute an old, internally valid SQLite file.

## Release-critical omissions

1. **Provisioned trust principal:** Windows protected service identity,
   SCM/DACL, signed executable and restricted protected state directory;
   Linux dedicated user, systemd hardening, read/write and parent-directory
   ownership/modes and supplementary-group/capability constraints.
2. **Secure storage acquisition:** current offline API uses a pathname
   and therefore has no trusted native handle, reparse/symlink defense,
   inode/file-id pinning or protection against rename while the DB opens.
   A protected broker must perform OS-rooted, anchored file acquisition.
3. **Policy authenticity and administration:** digest is caller-supplied
   and unverified. No authenticated IPC caller, signed policy, rootRef
   binding or epoch installation in the C4f arbiter exists. Runtime
   activation remains forbidden.
4. **Rollback, durability and race acceptance:** independently run
   unauthorized-user replace/unlink/rename/rollback attempts; abrupt
   process termination and power-failure simulations; concurrent
   updates from multiple processes; journal corruption/recovery; schema
   tampering; real Fsync/FlushFileBuffers and filesystem-specific checks.
5. **Operational safety:** enforce bounded I/O, cancellation and
   post-revocation no-unauthorized-byte-mutation native filesystem
   operations on both Windows and Linux. C5/D/E are not ready.

CI additionally performs strict cargo-deny advisory/license/registry
checks for this crate, Clippy `-D warnings`, and full Rust tests, but
passing them does NOT satisfy these unresolved security gates.
