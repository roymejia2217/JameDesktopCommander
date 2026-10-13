# T011-C4o — Windows SCM process-token audit contract (non-release)

**Stage:** OC-02, contract and test design; implementation is NOT accepted.
**Base:** protected `main` `dd5b317ed38d9ab1187d5466fba2b71eff39cda4`.
**Scope:** Windows SCM service process on ephemeral Windows GitHub-hosted CI only.

## Security question and boundaries

C4m proves that a real SCM-launched process uses the expected virtual service
account. C4n proves the service object's protected DACL and real nonadmin
denials. Neither establishes the full effective privilege and restricted-SID
set of the **running process token**. This contract must not treat a configured
account name, `sc.exe sidtype`, or successful service creation as token proof.

The subject is `jdc-authority-scm.exe`, running inside SCM under
`NT SERVICE\JameDesktopCommanderAuthority`. The token is kernel-issued.
The test harness is untrusted evidence unless it observes a decision computed
**inside the actual SCM process**. No user-host SCM installation is permitted.

Threats: token substitution, missing restrictive SIDs, unexpected enabled
privileges, elevated group membership, spoofed caller output, brief-process
inspection races, unchecked native buffer lengths and test bypasses.

## Selected native API contract

Use only documented Windows APIs through the existing pinned `windows-sys`
dependency, not ad-hoc token scanners or a new privileged helper:

1. `GetCurrentProcess` and `OpenProcessToken` with `TOKEN_QUERY`: acquire
   this SCM process's actual primary token without PID-based discovery.
2. `GetTokenInformation(TokenUser)`: retain the C4g expected virtual-account
   SID check using independently resolved `LookupAccountNameW`.
3. `GetTokenInformation(TokenGroups)`: inspect real group SIDs **and their
   attributes**; a disabled/deny-only SID is not an enabled administrator.
4. `GetTokenInformation(TokenRestrictedSids)`: prove the configured service
   SID actually occurs in the restrictive SID list and inspect its attributes.
   Do not substitute the `sidtype` registry value for this observation.
5. `GetTokenInformation(TokenPrivileges)`: enumerate LUIDs and enabled flags.
   `LookupPrivilegeNameW` may resolve privilege names; an unknown LUID is
   recorded as unclassified, never silently accepted as safe.
6. `GetTokenInformation(TokenIntegrityLevel)`: record integrity classification
   without presuming the level inherited by every supported Windows runner.
7. `GetTokenInformation(TokenType)`: require a primary process token.
   Evaluate `TokenElevationType` only if it changes an explicit security
   decision; a service is not an interactive UAC session.

Prefer one opened token handle, RAII closure, and bounded two-call queries.
Every returned length, element count, pointer and SID must be verified
against a small documented maximum **before dereference**. Refuse malformed,
oversized, missing, unexpectedly changing or inaccessible information.

## Trust and decision model

Separate **observation** from **authorization**. A token observation cannot
enable file access, policy state, IPC, a service `Running` status or a release.
Return an internal classified outcome:

- `E_TOKEN_UNVERIFIABLE`: API, size, layout, SID or privilege lookup cannot
  be verified without unsafe assumptions.
- `E_TOKEN_BOUNDARY_VIOLATION`: mandatory SID/group/attribute policy fails.
- `TOKEN_OBSERVED_DENY_ONLY`: all required fields were obtained and the
  explicitly approved minimum-privilege rules passed; policy stays absent.

No path, process argument, environment variable, JSON or test parameter
may influence expected SIDs or required attributes. Do not emit raw token
buffers, SIDs of unrelated principals, passwords or privilege inventories
into public logs. Use bounded categorical diagnostics and stable exit codes.

Before enforcing a whitelist of enabled privileges, establish a **real**
SCM-runner baseline, review each privilege against the broker threat model,
and then define the policy in version-controlled tests. In particular,
`SeImpersonatePrivilege` and `SeChangeNotifyPrivilege` must not be assumed
present or absent. Enabled `SeDebugPrivilege`, `SeTcbPrivilege`,
`SeCreateTokenPrivilege` or `SeLoadDriverPrivilege` warrant explicit
blocking review; the initial audit may not assert they are absent without
native evidence. Reject 'all unknown privileges are harmless'.

## SCM lifecycle / observable evidence

Reuse `native/authority-service/src/windows_scm.rs` and the governed
`test/security/t011-windows-scm-acceptance.ps1`; no extra service,
user-host installation or long-lived privileged process. The audit must
execute **after** the SCM dispatcher and control handler are registered,
but before the existing terminal `Stopped` service status.

Maintain code 1 for an authenticated, audited token whose protected
policy is unavailable; retain code 2 for failed OS identity; assign a
separate nonzero failure reason to token-audit rejection. The Windows
CI fixture must assert the precise final service-specific reason and
`Stopped` state, with no surviving process. Preserve the C4n DACL test
and cleanup in a `finally` block even when the token audit rejects.

Avoid sleep loops, polling for a process ID, or temporarily reporting
`Running` to make inspection easier. Exit-code evidence alone is not
sufficient: tests must also exercise negative cases for identity,
restricted-SID absence, attributes, malicious groups, enabled high-risk
privileges, corrupt buffers, and failed API calls through testable
policy/decoding functions. No forged environment-driven PASS.

## TDD and acceptance stages

**OC-03.1 — RED:** Add pure, Windows-independent tests for snapshot
classification and bounded parser invariants. Verify they fail against
the missing implementation; prevent generic nonzero errors passing.

**OC-03.2 — GREEN:** Introduce a focused Windows-only token module
behind an explicit interface; use RAII native handles and documented
`windows-sys` APIs. Keep Linux preflight unchanged, including its
supplementary-group checks. No dependency-version or public MCP changes.

**OC-03.3 — Real Windows acceptance:** Extend the existing required
`Native probe (win32-x64)` job, NOT a standalone optional check.
Build with pinned Rust 1.91.1, run Clippy with `-D warnings`, parse
PowerShell with its native AST parser, and run the real SCM acceptance.
Verify success and negative controls. No elevated tests on user hosts.

**OC-03.4 — Review and postmerge:** Observe RED / GREEN, regressions,
cargo-deny, CodeQL, Required CI, native Linux and Windows, candidate
checks, protected squash merge (without commit metadata overrides),
then revalidate the signed `main` commit and postmerge workflows.

## Unresolved decisions / explicit nonclaims

- The actual SCM token privilege baseline and integrity level are unknown.
- The exact least-privilege whitelist is not yet approved by real evidence.
- The inventory does not assess inherited handles, DLL load search paths,
  admin/SYSTEM compromise, authenticated IPC, state rollback, native
  handle-bound file I/O, revocation, or operational packaging.
- The CI runner's privileged setup principal is **not** the service token.
- The absence of `Running` is intentional, not an incomplete service test.

Production file operations remain **DENIED**. `releaseEligible` remains
false until the independent broker, policy custodian and D/E gates exist.

## Official platform references

- [GetTokenInformation](https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
- [TOKEN_INFORMATION_CLASS](https://learn.microsoft.com/windows/win32/api/winnt/ne-winnt-token_information_class)
- [SERVICE_SID_INFO](https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
- [Access Tokens](https://learn.microsoft.com/windows/win32/secauthz/access-tokens)
- [Privileges](https://learn.microsoft.com/windows/win32/secauthz/privileges)
