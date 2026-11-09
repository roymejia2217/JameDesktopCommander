# JDC installation and complete decommissioning contract

Status: **release-blocking, partially implemented**. Owner: #248; Linux adapter: #150; operator UI: #270; independent security gates #124, #139, #148. This inventory describes current behavior, not permission to delete arbitrary OS resources.

## Two separate life cycles

The Windows EXE and Debian DEB currently install **application files only**. The operator registers a managed remote tunnel separately. A passing package uninstaller does not prove the associated remote credentials, autostart services, network listeners or unrelated configurations were removed.

~~~mermaid
flowchart TD
  A["Verified JDC .exe or .deb"] --> B{"OS package manager"}
  B -->|Windows Inno per-user| W["App tree, HKCU uninstall entry, two shortcuts"]
  B -->|Debian dpkg and nFPM| L["App tree, /usr/bin/jdc, desktop launcher"]
  W --> I{"Separate authorized tunnel enrollment?"}
  L --> I
  I -->|No| N["No persistent JDC tunnel created by package"]
  I -->|Yes| O["Windows scheduled task + supervisor OR Linux systemd-user unit"]
  O --> P["Official tunnel-client + selected external credential/profile"]
  P --> Q["Authenticated outbound control plane + loopback local health"]
~~~

**Required future full removal** (not yet implemented as an integrated product):

~~~mermaid
flowchart TD
  A["Operator chooses full decommission and uninstall"] --> B["Inventory actual instance, exact OS owner and resource origin"]
  B --> C{"Owner and interactive local authority proven?"}
  C -->|No| X["BLOCK broad deletion; report unresolved resources"]
  C -->|Yes| D["Fence restart; disable + stop owned task/unit; prove no child/listener"]
  D --> E["Revoke provider-side credential by supported authorized channel"]
  E --> F{"Remote credential revocation proven?"}
  F -->|No| Y["Report manual provider revocation still necessary; not complete"]
  F -->|Yes| G["Delete only owned tasks, units, secret references and recorded settings"]
  G --> H["Run normal OS package uninstall"]
  H --> I["Compare post-state to baseline, test network/auth denial"]
  I --> J{"Every invariant met?"}
  J -->|Yes| K["Whole-system uninstall complete"]
  J -->|No| X
~~~

## Resource and ownership matrix

| Resource | Windows source / removal | Linux source / removal | Current status |
| --- | --- | --- | --- |
| Application runtime, MCP, official client, read-only operator UI, notices | Inno Files under app root; Inno uninstaller | nFPM payload under /opt/jame-desktop-commander; dpkg remove and purge | Package-only E2E proven. |
| Launchers / registration | HKCU ARP key + two per-user Start-menu shortcuts | /usr/bin/jdc, desktop launcher, dpkg registration | Created and removed in CI. |
| Managed autostart | Desktop Commander Windows Tunnel Task Scheduler task from explicit jdc tunnel install | User systemd unit jame-desktop-commander-tunnel.service and enabled symlinks | Independently installed by CLI, **not package-owned**. |
| Recovery | Optional JameDesktopCommander Tunnel Restart Supervisor task | systemd-user Restart policy | Windows CLI uninstall attempts supervisor deletion; still separate from EXE uninstall. |
| Other live-host resources | JameDesktopCommander UI Bridge, older ChatGPT Desktop Commander Remote / OpenCode tasks | Independent bridges/processes possible | **Origin unproven**: never delete by fuzzy name or process-family pattern. |
| Provider profile / credential | Official client profile and separately protected credential file | Official client per-user profile, credential source and systemd user environment | External/operator created; no package ownership. Provider-side key revocation is not implemented. |
| Startup, environment, firewall, ports | Package must not change Run/RunOnce, Startup folder, machine/user environment, persistent firewall, or leave app-root processes | Package must not change user-systemd or environment files and must remove its app files | Package-only regression checks; full tunnel removal unproven. |
| Logs, caches, rollback / settings | Independent operator/bridge/runtime directories may exist outside app root | User data and systemd journal outside /opt | No complete inventory/retention contract; never delete foreign data. |
| Privileged broker / FFI | Experimental functionality, not release-eligible | Experimental functionality, not release-eligible | #124/#139/#148 remain P0 blockers. |

## Required full-system acceptance (NOT yet met)

1. Capture a **secret-free baseline** before installation: native package registrations, exact task/service ownership and action, profile/credential provenance, startup, environment, firewall, listeners, processes and user data. Observe actual OS APIs, not assumed file names.
2. Package files are exclusively handled by Inno Setup or dpkg/nFPM. Operator-approved enrollment must bind each additional task, unit, credential source and policy change to an OS-verified owner and installed identity. A JSON file, marker or username alone cannot authorize deletion.
3. Every resource is classified as package_owned, jdc_managed, preexisting_external or unknown. Unknown is not silently deleted or declared cleaned. Record authorized changes durably before applying them, with crash-safe rollback and concurrency fencing.
4. On explicit full decommission, stop/disable and fence every owned service before package removal, verify disappearance of registered autostart and live child/listener, and decommission owned auxiliary components. Never remove similarly named foreign tasks or profiles.
5. Revoke remote provider credentials through a **supported authenticated channel**. Deleting local key material does not revoke a provider key; if revocation is unavailable, mark the uninstall security status incomplete and instruct the authorized operator to revoke the credential remotely. Never claim full completion without proof.
6. An optional preserve-settings choice must preserve only authorized non-secret preferences, never active remote access, reusable credentials or managed autostart. Do not delete unrelated user projects, audit records or another service's key.
7. Run normal OS package uninstall; prove removal and no residue. Test wrong owner, modified unit, symlink/junction, active tunnel, locked file, partial failure, power loss, repeated uninstall, downgrade, lost user bus, and delayed remote disconnect in isolated real Windows/Linux OS fixtures.
8. Re-scan before and after, including exact environment/startup/firewall rules and active network endpoints. Any unverified resource or provider credential means **NO-GO**; exit code zero from the package manager is insufficient.

## Verified today: package-level boundary

The GitHub Actions Windows candidate installs and removes a real Inno EXE, checking installed payload, Add/Remove Programs key, shortcuts, task/service preservation, a synthetic pre-existing profile, startup registration, environment, firewall and running installed-root processes. The Debian job uses real dpkg install and purge, checks package registration and file-tree removal, and compares user-systemd and environment sources without printing them.

The installed Windows host has independently provisioned and currently active remote tasks, outside the EXE's ownership. These tests do **not** operate on that live connection. The Linux managed service and provider remote-auth revocation are not exercised by package-only CI.

## Work ownership and release gate

- **#248 — lifecycle delivery owner**: managed enrollment, ownership registry, consent UI, decommission, remote key revocation, authorized data retention and crash-safe rollback. One active implementation slice at a time.
- **#270 — operator UI child**: accessible native local confirmation, recovery, and security status, after authority proof.
- **#150 — Linux adapter**: provenance-bound user-systemd install/removal and real clean-host full-cycle acceptance.
- **#124/#139/#148 — P0 security gates**: independent blockers, not waived by packaging tests.

Current stable public release decision: **NO-GO**. This document is a resource ledger and acceptance specification, not an assertion that managed services are already safely uninstalled.
