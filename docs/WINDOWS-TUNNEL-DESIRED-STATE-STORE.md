# Windows Tunnel Durable Desired-State Storage

**Status: non-operational research increment.** The state store does not run a
background service, alter Task Scheduler, start the tunnel or authorize recovery.

## File and trust boundary

The store requires a separately provisioned, absolute
`tunnel-desired-state.json` file. It never creates a missing state file,
because a missing or corrupt operator `stopped` decision must **not** become
an implicit `running` default.

The strict schema has `schemaVersion: 1`, a positive monotonic `revision`,
`desired: running|stopped`, `retryAttempts` (0..32) and `lastAttemptMs`
(null if and only if no attempt has been recorded). Unknown fields, malformed
JSON, invalid values, symlinks and multiply linked files are rejected.

Every mutation takes an exclusive `proper-lockfile` lock, reloads the current
disk revision, checks compare-and-set expectations and writes a durable
candidate with an exclusive temporary file and explicit flush. On Windows,
the existing Win32 `ReplaceFileW` helper performs the replacement.
The old state is not truncated in place.

## Security and operational limitations

- Provisioning, access-control lists, identity verification, operator
  authorization and authenticated intent updates are **not implemented**.
- Any compromised process allowed to write this file can forge a valid schema;
  schema validation and file locking do not provide cryptographic authenticity.
- Cooperative locks only coordinate compliant writers. Out-of-band changes
  require separate detection, attribution and fail-closed handling.
- The store cannot guarantee crash/power-loss durability without a validated
  Windows filesystem and power-failure test matrix.
- The recovery decision from PR #93 remains ineligible to execute unless
  the controller independently verifies operator authority, fencing/leases,
  process identity and real control-plane health.
- No production migration, automatic initialization or runtime hook exists.

## Required later acceptance

Cross-process compare-and-set with two isolated Node writers is covered by tests.
Still confirm crashed writer recovery,
stale-lock handling, file replacement failure injection, ACL/DACL enforcement,
power interruption behavior and strict observability. A successful unit test
must never be represented as validation of these later requirements.
