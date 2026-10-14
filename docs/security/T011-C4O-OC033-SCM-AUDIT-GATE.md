# T011-C4o / OC-03.3 — In-process SCM token audit gate

**State:** Pending independent real-SCM Windows CI and postmerge acceptance.
**Base:** Protected main `b996716fa6960217cd4107a40c7bb6ff958f2854`.
**Release:** Deny-only; `releaseEligible: false`. Not an installer or broker.

## Scope and trust boundary

The SCM dispatcher registers its service control handler, then checks the
actual kernel-issued service identity and invokes the OC-03.2 native
`observe_current_process_token()` function **inside that SCM process**.
No PID polling, test-runner process credentials, CLI token spoofing or
environment-based override is accepted. It still reports `Stopped` with
`ServiceControlAccept::empty()`; it never reports `Running`.

A separate outside-the-service, GitHub-hosted Windows fixture creates a
temporary SCM service with protected DACL, dedicated virtual account and
restricted SID. The existing fixture, not an optional CI job, proves that
a genuinely separate nonadministrator principal cannot mutate the service.
It then inspects the final SCM-specific error status, process exit and
cleanup in `finally`. Do NOT run this fixture on a user host.

## Exhaustive denial outcomes

| Code | Observation | SCM behavior / CI policy |
| --- | --- | --- |
| 1 | Kernel identity and token match synthetic minimum, but policy unavailable | Stopped; accepted *only* as non-release denial |
| 2 | Service identity does not match | Stopped; FAIL CI |
| 3 | Structurally verified token, enabled privileges not independently approved | Stopped; accepted *only* as fail-closed baseline observation |
| 4 | Mandatory token group, restricted SID or high-risk privilege violation | Stopped; FAIL CI |
| 5 | Native query failed, missing or invalid evidence | Stopped; FAIL CI |

The fixture checks `Win32_Service.ExitCode == 1066`,
`ServiceSpecificExitCode` is **exactly 1 or 3**, `State == Stopped`,
and `ProcessId == 0`. Code 3 never permits operations and never
constitutes a completed least-privilege review. General nonzero return
codes do not satisfy this acceptance. Codes 2, 4 and 5 must fail CI.

## TDD / local scope

- RED: Rust `E0432` for missing `scm_terminal_denial_code`;
  Node contract rejected missing in-SCM invocation and exact terminal
  error enforcement.
- Security regression: split the previously ambiguous `Unverifiable`
  outcome into `PrivilegeBaselineUnreviewed` versus invalid evidence.
  That change was proved RED before updating the classifier.
- GREEN: Rust pure outcome tests, bounded token observation regressions,
  Node SCM contract tests, official Rustfmt and Clippy `-D warnings`,
  and PowerShell AST parsing, on the isolated development worktree.

## Remaining risks and gates

The SCM service's actual enabled privilege names and group attributes
have **not yet been observed in the ephemeral runner**. The first native
CI acceptance might fail, legitimately, if the real token violates the
assumed minimum, including its restricted SID flags. Such failures
require evidence and policy review; do not weaken the fixture or declare
missing API evidence a success.

OC-03.2's identity preflight and token observer still open separate
process-token handles; this is bounded to the same short-lived process
but one-handle consolidation remains open for architectural review.
The current group policy detects enabled BUILTIN Administrators and
LocalSystem but is not an exhaustive group allowlist. Baseline approval,
inherited handles, DLL loading, authenticated IPC, protected custody,
revocation, native handle-bound I/O, C5/D/E remain unimplemented.

No installed Windows JDC service or tunnel is changed. Neither the
CI-only fixture nor the test runner authorizes production filesystem I/O.
