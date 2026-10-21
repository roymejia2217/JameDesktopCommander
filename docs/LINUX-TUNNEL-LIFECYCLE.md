# Linux tunnel lifecycle: user service, no privileged install

**Status:** development-only, non-release integration for issue #150. This
does not install a service on the user host and does not authorize SENAE data
access.

The JDC CLI exposes `node dist/index.js tunnel install|start|stop|status|uninstall`
on Linux. It uses **official `systemctl --user`**, without an intermediate
shell, hand-rolled watchdog, root service or privileged system directory.
The user must supply the already-installed official tunnel-client absolute
path, a profile directory and a profile name. Install invokes
`tunnel-client doctor --profile-dir ... --profile ... --explain` before any
filesystem mutation. No profile secrets or tokens are copied into the unit.

The service unit is stored at
`~/.config/systemd/user/jame-desktop-commander-tunnel.service` and created
exclusively with mode 0600. Existing units are never overwritten; no
`--force` or auto-repair mode exists in this first slice. Its parent
configuration directories must be ordinary directories owned by the
current user, not links to other trees. The unit executes the client directly
and uses `Restart=on-failure`, `NoNewPrivileges=yes`, `UMask=0077`,
`PrivateTmp=yes`. The user manager and effective non-root principal are
mandatory. If the bus is unavailable, installation must fail before
creating any file.

Starting enables and starts the unit via `systemctl --user enable --now`.
Stopping calls `disable --now`, preserving an intentional stopped state on
subsequent user-session startups. Uninstall requires an existing JDC-marked
unit and disables/stops it before removal and a manager reload. The
`status` operation checks actual service state; if active it resolves the
registered official profile using `profiles list --json` and reads only the
profile's local `health.url_file` reference, then invokes official
`health --json --url-file ... --require-control-plane-poll`.
A running unit without liveness, readiness and control-plane poll is
**not** a healthy tunnel; the CLI exits nonzero.

The unit is **not a privileged filesystem authority**: this feature must
not be confused with T011's blocked service and OS-principal custody
decisions. Process execution tools also require explicit user authorization
and are not constrained by `allowedDirectories`.

## Acceptance before any Linux deployment

- The TypeScript build, official Node tests and full PR CI must pass on the
  exact commit. Tests must prove unit content, rejected unsafe names,
  no-root policy, no-user-manager denial without side effects, non-overwrite,
  start/stop intent, and health/degraded/inactive outcomes.
- A real Ubuntu **user-manager** lifecycle test is still required on a
  disposable user session. Mocks are not a replacement for the real bus,
  CLI binary, profile authentication and reconnection. A clean Linux laptop
  acceptance must prove startup, restart, intentional stop, logout/login,
  network outage recovery, fresh ChatGPT MCP round trip and rollback.
- Standard official `tunnel-client` CLI and managed unit names must be
  independently verified. The binary path must be durable across upgrades.
  No root, manual tunnel process killing, shell-script service substitute,
  daemon replacement or copying secrets to systemd units.
- Security patch PR #146 is a predecessor; T011 #124/#139/#148, privilege
  #80, Linux release identity and signed distribution remain open. Do not
  merge/release this development PR without independent review and all
  applicable protected checks.

A green workflow on this slice is evidence for **CLI and user-unit contract
only**, not remotely connected Linux availability.
