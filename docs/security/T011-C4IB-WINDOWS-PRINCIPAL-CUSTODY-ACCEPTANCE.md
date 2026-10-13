# T011-C4i-b — Windows distinct-principal NTFS custody acceptance

**Status:** Experimental non-release proof. Protected baseline:
8fdb99b6d333a669356f29a14a284ae4eda33f66.

## Actual operating system trust boundary tested

The existing governed Native probe (win32-x64) job on an ephemeral
GitHub-hosted Windows 2025 runner compiles two offline Rust fixtures,
parses the PowerShell script, and executes it with standard Windows APIs.

The harness creates two distinct non-administrator local accounts:
jdc-ci-svc (owner) and jdc-ci-att (attacker), each with a distinct SID
and unpredictable, ephemeral credentials never printed to CI logs.
It creates a GUID-named directory under ProgramData and configures
explicit non-inherited NTFS DACLs:

- State: service-test account has Modify; SYSTEM and Administrators
  retain FullControl for provisioning and cleanup. Attacker is not granted access.
- Binary directory: both accounts have ReadAndExecute only.
- Attacker-owned directory: attacker has Modify. A canary and a valid
  old SQLite snapshot demonstrate successful execution and access.
- Fixture parent: both accounts may traverse; the attacker cannot
  replace the protected state directory through its parent.

PowerShell Start-Process -Credential launches separate processes with
each account's real Windows token. The owner must initialize epoch 1,
advance to epoch 2 and read it. The attacker must successfully write
its canary, read an old snapshot, and exercise append, overwrite,
rename, unlink, create, parent rename and DACL changes on its own
writable fixture before those same operations are tested for denial.
Actual attacker attempts to read,
append, create, overwrite the DB with epoch 1, rename, unlink, rename
the parent directory and change its DACL via icacls must all fail.
The owner must then read epoch 2; the database SHA-256 must be unchanged.
Failed positive controls, a successful unauthorized attempt, malformed
ACL inheritance, mismatched hash or cleanup failure fail the CI job.

The script is gated to a GitHub-hosted Windows runner as an accidental
execution guard, not as an unforgeable platform attestation. Never run
it on any installed user's Windows host. It does not contact JDC services,
network tunnels or runtime applications, and cleans up test accounts and
fixtures on the disposable runner.

## Explicit production blockers

- These are ordinary Windows local user SIDs, NOT the actual Windows
  SCM virtual service account NT SERVICE\\JameDesktopCommanderAuthority.
  The fixture is provisioned by the runner administrator. A production
  service identity and protected ACL-managed installation remain missing.
- Administrators and SYSTEM retain full control. No root/administrator,
  stolen-token, malicious elevated process or service compromise defense
  is demonstrated. A privileged rollback is still possible.
- The script exercises NTFS permission rejection, not power-loss
  durability, safe SQLite native handle acquisition or prevention of
  all pathname race conditions.
- Authenticated named-pipe IPC, broker-mediated policy updates, durable
  anti-replay anchoring, root handle confinement, linearizable revocation
  and C5/D/E acceptance are still open.
- The isolated Rust fixtures and PowerShell runner are not imported by
  production code, installed as a service or included in release packaging.
  T011 release eligibility remains false.

Local tests may validate syntax, Rust compilation, lint and CI wiring.
Only a successful independently executed Windows native CI job is evidence
of actual two-SID NTFS enforcement on that ephemeral runner.

Official API references: Microsoft Learn New-LocalUser, Start-Process
-Credential, .NET FileSystemAccessRule and Windows NTFS DACL controls.
