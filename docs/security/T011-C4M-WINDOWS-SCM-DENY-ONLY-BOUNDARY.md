# T011-C4m — Windows SCM deny-only service entry and identity acceptance

**Status:** Non-release feasibility and disposable runner acceptance only.
Protected main baseline: `c188c07eea9a0baac5d2dfea105660688d78f809`.

## Engineering choice: real SCM service protocol

Unlike a console executable, a Windows service must register a dispatcher,
implement a ServiceMain callback, register a service control handler, and
report its state through SCM. T011-C4g's Rust executable was a console-only
preflight. It must **not** be registered directly as a production service.

The new independent target `jdc-authority-scm` uses
`windows-service 0.8.1` (maintained Rust wrapper around Windows SCM),
pinned in the exact service Cargo.lock, to:

- Register the fixed service name `JameDesktopCommanderAuthority`
  through `StartServiceCtrlDispatcher` and a real ServiceMain callback.
- Register the control handler and acknowledge SCM interrogation without
  pretending to support STOP or accepting operational requests.
- Check the kernel process token using the existing `LookupAccountNameW`,
  `GetTokenInformation(TokenUser)` and `EqualSid` identity preflight.
- Report `Stopped`, never `Running`, and include a nonzero
  service-specific exit code: **1** when the dedicated virtual account
  was authenticated but protected policy is unavailable; **2** when
  the process token is not that virtual account.
- Reject interactive invocation outside SCM. On non-Windows platforms
  the target exits without registering or authorizing any operation.
- Never open a filesystem root, load a policy, create an IPC endpoint,
  accept a grant, mutate a file or enable a release candidate.

A successful SCM dispatcher return on process shutdown must **not** be
interpreted as a healthy service. CI evaluates the service manager's
final state and service-specific denial reason.

## Windows-only acceptance on an ephemeral GitHub-hosted runner

The existing **governed Native probe (win32-x64)** job builds and
strictly lints the new executable with Rust 1.91.1, parses the acceptance
PowerShell with the official parser, and executes an isolated
`t011-windows-scm-acceptance.ps1` fixture.

The fixture refuses execution without the GitHub Actions / Windows /
GitHub-hosted runner environment. These values prevent accidental
invocation but are **not unforgeable host attestation**. It uses
Microsoft `sc.exe` only inside the disposable runner to register a
**demand-start, own-process** service under the managed virtual account
`NT SERVICE\JameDesktopCommanderAuthority`. No password, LocalSystem
identity, boot registration, recovery restart policy or interactive
service installation is requested. SCM's documented restricted service
SID type is configured through `sc.exe sidtype`.

The compiled binary is staged into a GUID-scoped ProgramData test
directory with explicit non-inherited NTFS DACLs: SYSTEM and
Administrators retain FullControl for setup/cleanup, while the
independently resolved service SID gets ReadAndExecute. Its SHA-256
must match the freshly built binary. The fixture must prove that:

- SCM reports the intended virtual account, manual start and
  own-process type, rather than LocalSystem or a substitute account.
- Direct interactive launch of the same binary cannot succeed.
- A real `sc.exe start` request reaches the service. Whether the
  CLI reports initial success or failure is **not** the acceptance
  criterion; the final SCM state must be `Stopped`, with Win32 exit
  code **1066** (service-specific error) and service-specific code
  **1** (policy unavailable, not failed identity code 2).
- The service has no surviving process, the fixture is removed and
  the service registration is deleted even after a failed assertion.
  Errors in cleanup also fail the job.
- Neither the user Windows host, the installed JDC tunnel/runtime,
  nor any persistent account or service is modified.

The disposable runner acceptance validates a true SCM entry and
kernel-issued virtual token; it is stronger than textual inspection of
a `.service` file or an interactive console-only negative test.

## Explicit safety limitations / required next milestones

1. **Installation and identity:** ephemeral `sc.exe` registration is
   a CI acceptance mechanism only, NOT the deployment strategy.
   Production must use a reviewed signed/versioned package (evaluate
   WiX Toolset service declarations), account/ACL migration, recovery
   and uninstall, correct SCM service object DACL, executable integrity
   and restricted identity proof on real hosts.
2. **Privileges:** the test does NOT show immunity to Administrators,
   SYSTEM, stolen virtual-service tokens, service-host compromise,
   elevated file/path replacement, unsafe inherited handles or
   malicious DLL search paths. SCM object DACL adversarial tests and
   token privilege audit are still required.
3. **Protected state:** SQLite's atomic counter is not protected
   against replay by a principal capable of replacing its full file.
   A privileged independent policy authority, pinned OS handles,
   crash/restart and rollback proofs must be completed.
4. **Authorization:** named-pipe peer authentication, policy administration,
   epoch binding, root confinement, bounded cancellation and
   linearizable revocation remain absent. C5 handler migration, D/E
   hostile real-host tests and release packaging are still OPEN.
5. **Release guard:** service never reports `Running`, opens IPC or
   enables filesystem authorization. `releaseEligible` remains false.
   The result of a real Windows CI run is required before integration;
   a Windows local compiler PASS alone is insufficient.

Platform references: Microsoft Windows service virtual accounts,
`CreateService`, `SERVICE_SID_INFO`, `sc.exe create/config/sidtype`,
service status reporting; Rust `windows-service` dispatcher and status
handler APIs.
