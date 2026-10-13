# T011-C4i-a — Linux distinct-principal state custody acceptance

**Status:** Non-release, isolated GitHub-hosted Linux acceptance proof only.
Protected main baseline: `366dc8f5722cf26d8658c53d1dd3c73124cddac3`.
This does not install or modify any real Windows/Linux JDC service, start an
IPC broker, grant any MCP filesystem permission, or mark T011 release-ready.

## OS trust boundary under test

On the **disposable** `ubuntu-24.04` GitHub-hosted CI runner, the
existing T011 native security job provisions a fresh `jdc-authority`
system account through standard `useradd` and invokes code with `sudo`
under that exact identity. It verifies the fixed Linux
`getpwnam_r` + `getresuid` + `getresgid` preflight and creates a
synthetic SQLite v1 policy database in a `/tmp` test directory owned by
`jdc-authority` and restricted to mode 0700. The DB is mode 0600.

A **different** real principal, the system `nobody` account, is used
as the attacker. The test first establishes that this attacker can
execute commands and modify a canary it owns; otherwise an inability to
execute `sudo -u` could create a false security PASS. It then supplies
the attacker with a valid but stale database snapshot and demands that
every unprivileged attempt to browse, read, modify, create, overwrite,
rename, unlink, replay, rename the protected parent, or change the
parent permissions fail. The owner must still read epoch 2 and the
database SHA-256 must remain unchanged after all attacks.

An attack returning exit code 0, a missing identity, unexpected
preprovisioned service account, missing `sudo`, an unreadable owner
fixture, a changed digest or a wrong epoch makes the native CI job FAIL.
There are no skipped or silently accepted adversarial steps.

## Security scope and limitations

- This proves **actual kernel-enforced separation for ordinary Linux
  processes using two different UIDs** inside the ephemeral runner.
- GitHub runners have a privileged administrator/sudo capability.
  This test deliberately switches to `nobody` and **does not** protect
  against a malicious administrator, root process, stolen service
  credentials, a compromised service binary or host compromise.
- `useradd`, `chown`, `chmod` and `sudo -u` are standard host tools
  used for disposable acceptance fixtures, NOT a production installer.
  The script refuses to run outside a non-root, GitHub-hosted Linux
  runner and never touches persistent host storage.
- A secure Linux `systemd` service unit, supplementary-group
  restrictions, sandboxing, syscall/namespace confinement, pinned
  SQLite native file handles, `SO_PEERCRED` authentication, service
  upgrade/recovery and durability after power failure remain unproved.
- **Windows equivalent cross-principal validation remains OPEN**:
  provision and verify an independent Windows service identity, DACLs,
  service SID, state-file inheritance rules and adversarial real-host
  writes/renames/replays. Linux tests must not be counted as Windows proof.
- The test proves OS permission denial while protections exist; C4h
  still admits a full-store rewind when the attacker controls the
  state path or uses a privileged principal. There is no protected
  policy administration/update authority yet.

## Implementation and CI governance

The experiment uses only two offline Rust `examples/` binaries:
`identity_probe` checks the existing deny-only service credential
preflight, and `custody_fixture` creates/advances/reads **synthetic**
v1 SQLite data. These are build-time acceptance helpers, not runtime
packages, native APIs or a production broker.

`test/security/t011-linux-custody-acceptance.sh` runs only on
`RUNNER_ENVIRONMENT=github-hosted`, `RUNNER_OS=Linux` and GitHub
Actions, and denies execution as root or with preexisting service
principals. `shellcheck --severity=warning` and `bash -n` must both
pass. The proof runs inside the existing protected matrix job
`Native probe (linux-x64)`, **not an optional detached CI workflow**.
`test/test-t011-linux-custody-ci.js` guards this wiring.

These tests are necessary but not sufficient to enable production:
Windows acceptance, authenticated broker IPC, independently protected
durable anti-replay custody, OS-handle-rooted SQLite storage, native
filesystem transactions/revocation, and complete C5/D/E testing
are still mandatory.
