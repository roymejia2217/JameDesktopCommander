# T011-C4j — Linux supplementary-group identity hardening (non-release)

**Status:** Experimental credential preflight; independent broker provisioning,
authenticated IPC, trusted durable state and native authorization remain OPEN.
Base main: `c5ac269631f169e48afdc6b2f58381e3568fc65c`.

## Threat

The C4g service identity check compares kernel real/effective/saved UID and
GID to the dedicated `jdc-authority` account. Those checks do not constrain
**supplementary group membership**. A process with matching service UID/GID
but an inherited or injected unrelated group may have additional OS file
access, making the nominal principal check insufficient.

## Implemented deny-only control

The isolated `native/authority-service` Rust library additionally obtains
supplementary groups with Linux `getgroups(2)`. It denies when group
enumeration fails, the number of groups changes between reads, the group
list exceeds 32 entries, the expected primary group is root/zero, or any
supplementary GID differs from the dedicated service primary GID.
An empty supplementary list is allowed; a list containing only the service
primary GID is allowed. Untrusted environment and command-line strings are
not consulted.

The numeric group allowlist policy has Rust unit tests on the Windows
development host as well as Linux CI. The existing `Native probe
(linux-x64)` job runs the real, separate-user Linux acceptance fixture.
It first verifies a normal service identity succeeds and an attacker
identity fails. Then `setpriv` (from standard util-linux) launches
processes with **the service's actual UID and primary GID**, plus an
explicit extra GID from the `nobody` account. Two independent `id`
commands establish the intended UID and group membership; separate Linux
`/proc/self/status` credential checks confirm all real/effective/saved
UID and GID slots are correct before crediting any rejection to groups. The Rust identity probe MUST reject that contaminated
credential set, otherwise the protected native CI job fails.

The test invokes `useradd`, `sudo` and `setpriv` ONLY inside its existing
GitHub-hosted disposable Ubuntu runner, and the script refuses ordinary
host execution. It does not provision or modify local user accounts on
the Windows workstation, installed servers, services or tunnels.

## Remaining critical limitations

- This does **not** authenticate a Unix-socket IPC peer or tie an OS token
  to authorized native filesystem operations. The service binary still
  exits nonzero even when identity checks pass.
- This is a supplementary-GID constraint, **not** a complete restriction on
  effective/permitted/inheritable/ambient Linux capabilities, namespaces,
  inherited file descriptors, root privilege, setuid helper behavior,
  malicious administrators or compromised service code.
- A hardened, independently provisioned systemd unit with documented
  supplementary-group/capability restrictions, immutable executable
  identity, protected storage and audited upgrade/uninstall does not exist.
- C4h's valid-snapshot rollback vulnerability under hostile state-file
  ownership remains. The Linux and Windows C4i fixtures prove rejection
  only for specified ordinary-user trust boundaries.
- Authenticated Windows named pipes/Linux Unix sockets, pinned native
  handles, durable monotonic authority, revocation, all C5 handler migration
  and D/E operational acceptance remain release blockers.

Successful Rust tests and CI are necessary, **not** production clearance.
