# T011-C4k — Experimental systemd service provisioning contract

**Status:** Declarative Linux bootstrap only; NOT installed, packaged,
started or authorized for production. Protected main baseline:
`327050daeb3615b1e6aa9b76d118d72728356f04`.

## Standard platform mechanisms

This increment uses **upstream systemd** rather than scripts that
create a service, chmod arbitrary directories or write custom privilege
configuration. Two source-controlled, versionable declarative files
are located under `packaging/experimental/linux`:

- `sysusers.d/jdc-authority.conf` specifies a disabled-login static
  `jdc-authority` system user and its dedicated primary group, with
  UID/GID allocated by systemd. It does not modify group membership
  of any existing account or request a fixed numeric UID.
- `systemd/jdc-authority.service` defines a non-installable,
  deny-only `Type=exec` service. It runs as `jdc-authority`, retains
  no ambient or bounding Linux capabilities, forbids privilege gain,
  sets a restrictive umask and creates separately owned state and
  runtime directories of mode 0700 via `StateDirectory=` and
  `RuntimeDirectory=`. Filesystem and process protections rely on
  systemd's maintained sandboxing directives.
- The unit has **no [Install] section** and sets `Restart=no`.
  `ExecStart` names a future package-owned executable at
  `/usr/libexec/jdc/jdc-authority-service`. That path is a packaging
  contract and MUST NOT be created or installed on the user's host
  by this increment. It is not a general-purpose shell script.
- The current Rust authority binary still rejects startup after
  identity verification with `E_POLICY_UNAVAILABLE`: neither a
  protected policy store, authenticated IPC nor pinned filesystem
  roots exist. `StateDirectory=` alone is **not** trusted anti-replay
  state nor a durable policy authorization protocol.

## Independent acceptance and failure policy

The existing governed **Native probe (linux-x64)** job in
`t011-capability-feasibility.yml` builds the exact pinned Rust
`jdc-authority-service` crate. On an ephemeral GitHub-hosted Ubuntu
runner, it validates the account fragment with the official
`systemd-sysusers --dry-run` (no account modification), using an
existing absolute path resolved by GNU `realpath -e`. Ubuntu 24.04
searches its system configuration directories when the positional
argument is a relative path; passing the repository-relative path
previously caused an incorrect file-not-found failure. The service
unit is also supplied to `systemd-analyze verify` by resolved absolute
path. The runner then copies the test-built binary to the declared path **on that runner only**, then
runs the official `systemd-analyze verify` on the unit. A missing
runner indicator, preexisting binary at that path, build failure,
unknown directive or systemd validator error must FAIL the native job.

The installed test binary is never started or registered as a systemd
service in this increment; the disposable GitHub runner is destroyed
after the job. Standard tools are used strictly for validation, not as
an application-specific installation utility.

A Node regression checks the source files and their placement inside
the existing native CI gate (not an optional detached workflow).
It also requires the unit to have no install section, no lifecycle
shell hooks, no broad filesystem write path, no capabilities and no
restart loop.

## Security and production acceptance still missing

1. **Packaging and signer:** an independently reviewed signed/versioned
   native package must own the executable, unit, account fragment,
   permissions, update, uninstall and recovery. Verify ownership and
   integrity of the actual executable and unit at runtime.
2. **Provisioned service acceptance:** launch via PID 1 on a disposable
   Ubuntu host and separately prove actual UID/GID/supplementary groups,
   kernel capabilities, sandbox options, state/run directory modes,
   cross-identity access denials, service stop/restart and diagnostics.
   `systemd-analyze verify` alone does NOT prove any of these.
3. **Trusted storage:** a separate protected policy administration
   interface, securely acquired database handles, atomic durable epoch
   transitions, adversarial rollback/crash tests and fail-closed recovery
   are still missing. A privileged administrator or compromised service
   account can still replay the SQLite state file.
4. **Real broker:** authenticated Linux Unix socket/Windows named-pipe
   peer credentials, validated root handle confinement, transaction
   synchronization, bounded cancellation and full C5/D/E migrations
   remain OPEN. The Windows SCM service needs a distinct implementation
   and independent Windows acceptance.
5. **Release gate:** neither installing this unit nor enabling release
   eligibility is approved. No changes to the live tunnel, operating
   system services, accounts, user settings or production MCP handlers.

Platform references: official upstream systemd `sysusers.d(5)`,
`systemd.exec(5)`, `systemd.unit(5)`,
`systemd-sysusers(8)` and `systemd-analyze(1)`.
