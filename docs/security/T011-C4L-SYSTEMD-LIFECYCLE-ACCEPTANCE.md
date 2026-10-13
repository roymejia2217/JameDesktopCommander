# T011-C4l — Real PID 1 systemd fail-closed acceptance (experimental)

**Status:** CI-only Linux service lifecycle proof. Protected main baseline:
`2e38173a6ae310fcee65bc359bdc2e714dc15fe9`.
Neither a production package nor a functional broker is implemented.

## Scope and standard tools

The existing governed `Native probe (linux-x64)` job runs on an
ephemeral Ubuntu 24.04 GitHub-hosted runner. It applies the reviewed
`sysusers.d` fragment using official `systemd-sysusers` to create the
locked `jdc-authority` account **only on that runner**, after first
checking no such account/group exists. This replaces the older
`useradd` fixture so the same dedicated account is used by the Linux
cross-principal custody and actual unit lifecycle tests.

The runner builds the pinned Rust authority executable. Before
launch, the test verifies that the installed executable is root-owned
and byte-for-byte identical to that build (via standard `cmp`). This
prevents an unrelated executable from satisfying the journal checks.
The script
`test/security/t011-systemd-lifecycle-acceptance.sh` refuses non-GitHub
hosts, root invocation, missing systemd PID 1 or preexisting unit/state
paths. It temporarily places the **existing reviewed unit** into
`/run/systemd/system` (ephemeral), reloads the manager with
`systemctl daemon-reload` and calls `systemctl --wait start` with a
bounded 30-second GNU `timeout` (5-second termination grace). The
initial command may return success for `Type=exec` simply because PID 1
successfully executed the binary; this does **not** mean the service
is operational. The test waits for actual termination, then requires
systemd's final result, exit code and journal to prove denial. The
binary is deliberately deny-only and **must exit unsuccessfully** with status 1,
reporting `E_POLICY_UNAVAILABLE` to the real systemd journal. An
`E_IDENTITY_REQUIRED` message, successful start or unexpected exit
state is a failure. The CI test never enables or installs the unit for
automatic boot and the unit declares `Restart=no`.

The acceptance reads actual systemd properties via `systemctl show`:
`User`, `Group`, `Result`, `ExecMainStatus`, `Restart`,
`NRestarts` and `NoNewPrivileges`. It requires the surviving state
directory `/var/lib/jdc-authority` to be owned by the dedicated UID
and GID with mode 0700, writable by the owner and inaccessible to a
different ordinary principal (`nobody`). It does not infer success
from textual configuration alone. Official `journalctl` must confirm
the exact expected denial after the process passes kernel-backed
UID/GID/supplementary group identity checks.

The test uses a bounded unit start timeout (`TimeoutStartSec=15s`)
and an EXIT trap to stop/reset the ephemeral unit, remove its
`/run/systemd/system` file and reload the manager. Cleanup failures
also fail CI. The GitHub-hosted runner is discarded after the job.
This work NEVER modifies local Windows accounts, the installed JDC
runtime, network tunnels, host services or production state.

The acceptance script is syntax-checked with `bash -n` and linted
with `shellcheck --severity=warning` inside the existing Linux native
job. Tests guard the required account provisioning and mandatory
service acceptance step; no detached optional workflow is introduced.

## Limits — not production authorization

- This proves **a single failed systemd launch** with the dedicated
  ordinary service principal, the reported service properties and the
  measured permissions of the persistent state directory on an
  ephemeral Ubuntu runner. It does NOT prove an operating live broker.
- The current binary opens no IPC listener, cannot read or authorize a
  policy store and performs no filesystem mutation. Its failure is
  **required**, not a service-health success. PID 1 start failure must
  never be reclassified as a production-ready service.
- The runtime directory normally disappears after the process exits,
  so this increment does NOT claim to have measured its permissions
  while an active service process is running. No sandbox enforcement
  adversarial test, kernel capability inspection of a live process,
  power-failure recovery, privileged rollback protection or restart
  migration has been completed. `systemctl show` cannot independently
  establish every kernel restriction.
- Root and administrators, compromised service credentials and a
  compromised or replaced executable remain outside the tested
  unprivileged custody boundary. C4h's privileged whole-database replay
  remains possible without independently protected policy authority.
- A signed/owned package with safe update/recovery, Windows SCM service
  parity, authenticated Unix socket/named-pipe IPC, OS-rooted native
  storage and file handles, revocation with bounded cancellation,
  and full C5/D/E hostile real-host acceptance are still required.

**Release status:** T011 blocked. No installation or service enablement
is authorized beyond the disposable acceptance runner.

Upstream mechanisms: `systemd-sysusers(8)`, `systemctl(1)`,
`systemd.exec(5)`, `systemd.service(5)`, `journalctl(1)`.
