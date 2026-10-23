# Linux tunnel lifecycle: user service, no privileged install

**Status:** development-only, non-release integration for issue #150. This
does not install a service on a development host and does not authorize
processing protected or confidential documents.

The JDC CLI exposes `node dist/index.js tunnel doctor|install|start|stop|restart|status|uninstall`
on Linux. It uses **official `systemctl --user`**, without an intermediate
shell, hand-rolled watchdog, root service or privileged system directory.
The user must supply the already-installed official tunnel-client absolute
path, a profile directory and a profile name. The explicit `doctor` CLI
preflight verifies the existing user manager, binary and profile without
creating a JDC unit. Install invokes
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
`status` operation checks actual service state. If active, it requires
exactly one official profile matching the registered name from
`profiles list --json`. The returned profile file and the registered
profile directory are resolved to canonical paths; files outside that
directory, including sibling paths with matching text prefixes or
symlinks escaping the directory, are rejected before YAML loading or
the official client health request. Only then does it read the selected
profile's `health.url_file` reference and invoke
`health --json --url-file ... --require-control-plane-poll`.
A running unit without liveness, readiness and control-plane poll is
**not** a healthy tunnel; the CLI exits nonzero. This path-selection
guard does **not** provide race-free OS-object custody: hard links,
mounts and same-principal concurrent modification remain outside its
proof and subject to independent T011 security review.

The unit is **not a privileged filesystem authority**: this feature must
not be confused with T011's blocked service and OS-principal custody
decisions. Process execution tools also require explicit user authorization
and are not constrained by `allowedDirectories`.

## Acceptance before any Linux deployment

- The TypeScript build, official Node tests and full PR CI must pass on the
  exact commit. Tests must prove unit content, rejected unsafe names,
  no-root policy, no-user-manager denial without side effects, non-overwrite,
  start/stop intent, and health/degraded/inactive outcomes.
- The independently restored Linux candidate already runs an actual Ubuntu
  **user-manager** lifecycle test with its bundled Node runtime and a
  disposable synthetic tunnel client. It validates installed unit contents,
  start/restart/stop behavior, loaded drop-in rejection, recovery from an
  altered managed unit and the packaged CLI status contract. This establishes
  real local systemd behavior, not remote authentication.
- The synthetic failure-recovery acceptance uses the official
  `systemctl --user kill` operation **only inside disposable CI** to
  terminate that test process abnormally. It requires a new live MainPID,
  an increased systemd NRestarts counter and a healthy packaged CLI result,
  without invoking JDC start/restart during recovery. The wait is bounded;
  missing recovery fails the test. This proves `Restart=on-failure`
  under controlled conditions, not recovery from an actual network outage.
- Separate clean-workstation acceptance must still prove official client
  authentication, login/logout behavior, outage reconnection, a fresh
  ChatGPT MCP round trip, rollback, and persistent executable paths.
- Standard official `tunnel-client` CLI and managed unit names
  must be independently verified. Do not use manual process termination as
  an operational recovery policy. No root, shell-script service substitute,
  daemon replacement or copying secrets to systemd units.
- Security patch PR #146 is a predecessor; T011 #124/#139/#148, privilege
  #80, Linux release identity and signed distribution remain open. Do not
  merge/release this development PR without independent review and all
  applicable protected checks.

A green workflow on this slice is evidence for **CLI and user-unit contract
only**, not remotely connected Linux availability.

## Explicit restart semantics

The Linux CLI delegates `restart` to the official `systemctl --user try-restart`
only after verifying the managed unit is enabled and active. The native
conditional operation also avoids reviving a unit that becomes inactive
after that check and before the manager processes the restart request. It
must never reactivate an inactive or deliberately stopped unit. A successful restart
acknowledges only the user-manager operation: `status` separately verifies
the tunnel's authenticated control-plane readiness.

## Pre-install diagnostic contract

Invoke `tunnel doctor` with the same three explicit install options. It
requires a non-root Linux user and a working `systemctl --user` manager,
verifies the official client executable and profile directory, then executes
the client's maintained `doctor --explain` preflight. JDC does not create a
unit or start services in this action. The structured response reports only
the action and managed unit name, never the supplied profile directory,
executable path, credentials, or contents. The official client is responsible
for its own diagnostic behavior. A successful result proves prerequisite
validation only, **not remote authentication, connection or deployment**.

External `systemctl --user` and official `tunnel-client` failures are reported
with separate stable error categories, never by forwarding arbitrary command
messages or causes. External diagnostics may contain absolute profile paths or
bearer material; operators should use the maintained client's protected
private diagnostics for detailed troubleshooting rather than public CLI logs.
The command still exits nonzero and preserves fail-closed behavior on errors.

## Loaded service definition integrity

Validating the JDC-managed service file alone does not validate the service
configuration that systemd actually loads. Before `start`, `restart` or
`status`, JDC now inspects `FragmentPath`, `DropInPaths`, `LoadState` and
`NeedDaemonReload` through the official `systemctl --user show` interface.
It requires the exact canonical JDC-owned fragment, no manager-loaded drop-ins,
a loaded unit and no pending unit reload. Missing or malformed properties fail
closed, without printing paths or manager metadata. The guard covers systemd's
full resolved unit/drop-in search paths (including name-prefix and type-wide
drop-ins); it does not substitute an ad hoc search of one directory.

The integration test adds a harmless `Environment=` override through an
actual temporary user-service drop-in, reloads the real Ubuntu manager and
requires the packaged CLI to reject both `status` and `restart` without
restarting the existing process. It removes the override and reloads the
manager before continuing normal lifecycle acceptance.

`stop` and `uninstall` intentionally remain available even after such
a configuration change, so an operator can disable a suspect service. This
manager-state check does not create a security boundary against arbitrary
malicious processes running as the *same* OS principal; a reviewed deployment
identity and privilege policy are separate requirements.

## Recovery from a modified managed service

The execution guard applies to `start`, `restart` and `status` and rejects
any changed managed unit or manager-loaded override. An operator must still
be able to stop an already-running suspicious unit and remove its JDC-owned
main unit file. `stop` and `uninstall` therefore require a regular
user-owned, non-group/world-writable service file with the exact JDC
management marker, **without trusting or executing any modified ExecStart
directives**. An unrelated unit or link is never deleted by this contract.
Both recovery operations invoke only `systemctl --user disable --now`; the
uninstall then removes the owned unit and reloads the manager. Foreign
drop-in files are deliberately not deleted without independent ownership
verification, and will still be rejected by the effective-unit check.

The Linux Node regression test checks rejection for start/restart/status and
successful stop/uninstall on a modified JDC-marked file, plus denial on an
unrelated file. The Ubuntu portable acceptance similarly mutates the unit
after stopping the synthetic process and verifies safe recovery through the
packaged CLI. These tests do not grant an attacker with the same OS principal
a distinct security boundary.

## Executable path custody (partial fail-closed gate)

Before `doctor` or `install` executes the official client, JDC resolves the
provided binary path canonically, checks it is an executable regular file
owned by root or the current Linux UID, and inspects its canonical parent
directories up to the filesystem root. Group/world-writable executables or
directories are rejected. A **root-owned sticky directory** (such as `/tmp`)
may be traversed because other UIDs cannot rename existing entries there;
a private descendant must still satisfy the ordinary ownership/mode checks.
The installed unit records the verified canonical executable path rather
than the user's original symlink.

Before `start`, `restart`, or `status`, JDC additionally requires the
stored executable to resolve to the **same** canonical location and pass
these ownership/mode checks again. Its explicit recovery commands `stop`
and `uninstall` intentionally do not execute or validate the client so
an operator can disable a suspect unit.

The Linux regression covers group/world-writable executable bytes,
a writable executable parent, refusal before doctor/service activation,
an accepted private-user fixture and recovery after trust loss.
These are **point-in-time checks, not full executable attestation**:
same-UID mutation, racing path replacement, bind mounts and publisher
identity remain outside their guarantee. For a production service, require
separately reviewed official-client provenance, update policy and
real-device authenticated/reconnection acceptance; do not infer any of
those from the successful client `doctor` result alone. This remains a
non-release feature.

## Linux user-directory integrity gate

The initial installer and every subsequent `start`, `restart`, `status`
and `uninstall` operation check the canonical HOME, all parent directories
from the filesystem root down to HOME, and the managed user-unit directories.
HOME and its managed descendants must be owned by the effective user and
not group/world writable. Higher ancestors may be owned by root or the user,
but may not be group/world writable except root-owned sticky directories
(such as the conventional `/tmp`) that protect existing entries from
replacement by unrelated users. Merely checking ownership of the unit
file or HOME is insufficient if an earlier path component can be changed
by another principal.
The installer creates missing private directories where supported, but
existing insecure directories are rejected; start/status/uninstall never
create missing directories. The operator can correct directory permissions
outside JDC using documented OS administration procedures.

Emergency `stop` remains available when directory modes are compromised,
provided the service file still passes its existing regular-file, ownership,
permission and JDC-marker checks. This invokes only the fixed
`systemctl --user disable --now` action and does not trust execution
directives or remove the file. `uninstall` refuses to unlink from a parent
writable by another principal. The negative tests verify that no activating
manager operation occurs and that the owned unit cannot be removed through
an unsafe directory.

This mode/ownership guard does not constitute a separate security boundary
against arbitrary processes running as the **same OS user**, nor does it
remove the independently required native T011 confinement gates.
