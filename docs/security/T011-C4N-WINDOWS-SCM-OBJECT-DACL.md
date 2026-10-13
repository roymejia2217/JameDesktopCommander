# T011-C4n — Explicit Windows SCM service-object DACL (non-release)

**Status:** Deny-only security acceptance on a disposable runner.
Base protected main: `5fd6882395a50b556ce14e8164ff9035151b3da3`.
The real Windows host, installed JDC tunnel and runtime are untouched.

## Threat and boundary

C4m established a genuine Windows service entry operating with its
`NT SERVICE\\JameDesktopCommanderAuthority` virtual identity and an
SCM restricted SID. That did not yet assert the *service object's own*
DACL. NTFS file permissions and token identity checks cannot prevent
an ordinary client from starting, stopping, reconfiguring or deleting
a service if the SCM object's access mask grants those rights.

Microsoft documents the distinct SCM service-object rights
`SERVICE_CHANGE_CONFIG` (0x0002), `SERVICE_START` (0x0010),
`SERVICE_STOP` (0x0020), `DELETE` (0x10000),
`WRITE_DAC` (0x40000) and `WRITE_OWNER` (0x80000).
These rights must not be granted to untrusted identities.

## Declarative experimental access contract

`packaging/experimental/windows/jdc-authority-service.sddl` is a
**version-controlled SDDL descriptor**, not a custom ACL formatter.
Its `D:P` flag protects the DACL from inherited ACEs. Exactly three
allow ACEs are permitted:

| Windows principal | SID | Service access mask |
| --- | --- | --- |
| LocalSystem | S-1-5-18 | 0xF01FF (service full control) |
| Administrators | S-1-5-32-544 | 0xF01FF (service full control) |
| Authenticated Users | S-1-5-11 | 0x2008D (read-only service query/interrogate) |

The Authenticated Users mask contains `SERVICE_QUERY_CONFIG` (1),
`SERVICE_QUERY_STATUS` (4),
`SERVICE_ENUMERATE_DEPENDENTS` (8),
`SERVICE_INTERROGATE` (0x80), and `READ_CONTROL` (0x20000).
It deliberately excludes start/stop, changing service configuration,
custom control, deletion, changing the DACL and changing ownership.
There are no unexamined additional allow or deny ACEs.

## Mandatory actual-Windows acceptance

C4n extends **the existing governed Windows native security job**,
not a new optional workflow. Its already ephemeral-only
`t011-windows-scm-acceptance.ps1` fixture creates the deny-only service
with the official Microsoft `sc.exe` API, configures the restricted
service SID, sets the **explicit** source-controlled DACL via
`sc.exe sdset`, queries it back using `sc.exe sdshow`, and parses its
security descriptor with .NET `RawSecurityDescriptor`.

Before crediting denials, the fixture creates a distinct temporary
non-administrator local user with an unpredictable password kept only
in the runner process. That account must **succeed** in querying the
service (`sc.exe query` and `qc`). With the *same real token*, it must
then receive the **exact Win32 ERROR_ACCESS_DENIED (5)** when attempting
to configure autostart, start, stop, change the DACL or delete the
service. A different failure, nonexistent service, broken process
launch or invalid arguments are NOT accepted as a security pass.

The descriptor is re-read after adversarial operations and must match
its exact pre-attack state; the SCM start account, manual start mode,
process type, final `Stopped` and service-specific denial code 1
remain governed by the previous C4m acceptance. Temporary local
accounts, stage files and the SCM service are removed in a `finally`
block; cleanup failures fail CI.

Local Windows validation additionally parses the fixed SDDL with the
standard .NET security descriptor parser, checks its actual ACE masks,
parses PowerShell without executing this acceptance on the user host,
and executes TDD RED→GREEN Node contract tests. All full CI gates,
including CodeQL and source isolation, must independently pass.

## Exclusions and next mandatory stages

- Only the **SCM object access control** is assessed here; its DACL
  is separate from executable and state-directory NTFS ACLs. This
  incremental proof does not cover a production service installer or
  packaging; the SDDL is only applied in ephemeral GitHub CI.
- SYSTEM and Administrators retain service control; this does NOT
  defend against elevated compromise or guarantee integrity of the
  installed executable or persistent policy DB.
- The deny-only service exits quickly. The fixture does not inspect
  the full *running process token privilege set*, restricted SID
  attributes or inherited handles. That audit is a separate milestone.
- Windows package lifecycle, protected rollback-resistant policy
  custody, authenticated named-pipe/Unix-socket IPC, OS-rooted native
  filesystem operations and linearizable revocation remain missing.
- T011-C5 handler migration, T011-D hostile testing and T011-E
  operational/release acceptance remain OPEN. The service never
  reports Running and cannot grant file I/O. `releaseEligible` stays
  false.

Authoritative reference: Microsoft Learn, **Service Security and Access
Rights** (Win32). The exact rights above follow that public contract;
no custom access-control library or installer script was introduced.
