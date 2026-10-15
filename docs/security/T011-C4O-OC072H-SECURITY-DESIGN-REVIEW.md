# T011 C4o / OC-07.2h — Adversarial SCM receipt design review

**Status:** REVIEW FINDINGS; NOT APPROVED FOR IMPLEMENTATION.
**Parent design:** [OC-07.2g](T011-C4O-OC072G-CONFIDENTIAL-RECEIPT-PROTOCOL.md).
**Tracking:** [OC-07 issue #80](https://github.com/roymejia2217/JameDesktopCommander/issues/80).
**Baseline:** protected `main` at `136f93718cbc46e0400c8c157ca0706edb0f11cc`.
**Authority:** no independent security sign-off or operational authorization.

## Scope and safety invariants

This review interrogates the design gates in OC-07.2g, not an exporter.
It adds no executable code, dependency, workflow, collector, recipient,
IPC listener, cryptographic key, token serialization or CI artifact.
The SCM stays deny-only and terminal `Stopped`; `releaseEligible: false`.
The issue remains open. Real Windows privilege records are still unreviewed.
Passing CI validates the documentation change, not the proposed protocol.

## Reviewed evidence and limits

- GitHub PR #90 integrated the *proposal*, not an authorization.
- OC-07.2a–d hold privately owned SCM observations in process memory.
- OC-07.2e/f constrain two official public artifact upload locations;
  they do not inspect every log, archive, reusable action or egress path.
- Windows documents that default pipe security grants access beyond
  the two intended endpoints; an explicit protected DACL is essential.
- Windows pipe client/server PID inspection returns an identifier, not
  a cryptographic authentication proof or an immutable process identity.
- Named-pipe impersonation failure leaves the caller's original context;
  a privileged server must fail before processing a request.
- GitHub-hosted runners remain an accepted-or-rejected provider trust
  boundary, not an attested secure enclave.

## Security decision matrix — all controls are proposals

The owner column names the approval *role*, not an assigned individual.
Evidence means existing support, not proof that the proposed control works.

| ID | Boundary / requirement | Existing evidence | Required control | Negative proof | Owner / status |
| --- | --- | --- | --- | --- | --- |
| R1 | Authentic SCM origin | Private token snapshot | Kernel token + live SCM registration and image linkage | Forged SID, direct launch, swapped binary | Windows security / OPEN |
| R2 | Unique live process | No active IPC | Pipe peer PID + held process handle, creation identity, live token checks | PID reuse, restart between checks | Windows security / OPEN |
| R3 | Endpoint isolation | Design only | Explicit protected pipe DACL, local-only policy and exclusive first instance | Squatting, low-privilege or remote connection | IPC reviewer / OPEN |
| R4 | Impersonation boundary | Design only | Check every native return; restore context; deny on failure | Failed impersonation, inherited handle | IPC reviewer / OPEN |
| R5 | Single authorized exchange | Proposed nonce | Bound one-use challenge, attempt and exact service instance | Replay, duplicate, concurrency, timeout | Protocol reviewer / OPEN |
| R6 | Crypto recipient custody | No approved key | Independent key authentication and offline private-key owner | Key swap, revoked recipient | Custodian / BLOCKED |
| R7 | Cipher and message integrity | No tool approved | Pinned maintained standard cipher, offline decrypt verification | Corrupt ciphertext, downgrade, format confusion | Crypto reviewer / BLOCKED |
| R8 | Provenance | PR signature and CI | Verify source, tree, build, both binary digests and SCM instance independently | Repacked binary, false workflow labels | Build security / OPEN |
| R9 | No plaintext egress | In-process snapshot | Memory-only plaintext, explicit egress inventory, fail-closed logging | Log, dump, artifact and exception leakage | Security reviewer / OPEN |
| R10 | Provider trust | Public ephemeral runner | Explicitly accept or reject privileged-host memory exposure | Simulated host compromise; threat-model limit | Risk owner / BLOCKED |
| R11 | Retention and cleanup | Proposed 24-hour bound | Controlled destination, cancellation, lifetime and incident response | Failed delete, duplicate receipt, aborted job | Evidence custodian / BLOCKED |

## Concrete review requirements

### Identity and IPC: R1–R5

- Define which component creates the pipe and the exact Win32 calls,
  token rights, verification order and process-handle lifetimes.
- `GetNamedPipeClientProcessId` and `GetNamedPipeServerProcessId`
  are candidate correlation signals only. Bind a process handle and
  creation identity before checking token, SCM registration and image.
  A lack of query permission is denial, never a bypass.
- Evaluate `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  `PIPE_REJECT_REMOTE_CLIENTS`, explicit DACL and minimal rights.
  Verify the chosen flags' behavior on supported Windows builds.
- If impersonation is needed, check `ImpersonateNamedPipeClient`,
  validate the expected thread token and reliably `RevertToSelf`.
  Do not continue a request after any authentication or revert failure.
- Specify nonce lifetime, bounded frame length, exactly-once receipt
  policy, cancel/reconnect semantics and simultaneous-client rejection.
  Do not assume timestamps, process names or GitHub labels authenticate.

### Custody, confidentiality and provenance: R6–R11

- Authenticate the public recipient outside the workflow. Record
  independent owner, key fingerprint, rotation, revocation and approval.
- Evaluate official `age` and interoperable implementations; no package,
  key, binary or executable exporter is selected by this review.
  Encryption integrity cannot independently attest SCM origin.
- Require exact source/tree, signer, job attempt, binary digests, OS and
  SCM configuration from separately checked sources, not receipt text.
- Define and audit every egress mechanism before claiming confidentiality.
  A static official-upload allowlist is necessary but insufficient.
- Separate verifiable deletion of staged artifacts from claims about
  sanitizing memory on an untrusted hosted runner; do not claim that
  guest-level cleanup proves absence of provider-side copies.
- Resolve whether the provider/administrator memory-exposure risk is
  acceptable. Ciphertext produced *after* observation cannot eliminate it.

## Falsifiable acceptance plan (not executed)

1. Synthetic parser contract: reject duplicate frames, overlong length,
   stale challenge, altered provenance and unknown format/version.
2. Windows ephemeral SCM: attacker attempts pipe squatting, remote
   connect, SID forgery, token query denial, process restart and PID reuse.
3. Windows impersonation: force native call failure and verify no
   privileged work occurs in the service's original security context.
4. Crypto fixture only: key substitution, revoked recipient, corrupted
   ciphertext, unsupported version and offline verification failure.
5. Confidentiality tests: deliberate stderr, archive, crash-dump,
   exception and cancellation paths; detect any plaintext disclosure.
6. Repeated/parallel attempts: verify one accepted observation at most,
   explicit denial of replay and deterministic cleanup after interruption.
7. Provenance tests: replace a binary after hash collection, change SCM
   registration and fabricate a workflow label; reject all mismatches.
8. Review all third-party action, log, temporary archive and outbound
   traffic surfaces; never infer global confidentiality from two uploads.

No test in this section has been run or implemented by this increment.
The tests require an approved isolation and observation protocol before
any confidential SCM evidence can be captured.

## Decision gates and next eligible work

- **Proposed design review:** may be discussed and amended independently.
- **Recipient custody, crypto, IPC and runner risk:** NOT APPROVED.
- **Active transport, real-token export, OC-07.3, C5, D, E:** BLOCKED.
- **Allowed next slice:** offline synthetic contract fixtures or a
  documented Windows API feasibility assessment that never handles
  private SCM evidence or opens an operational export channel.
- **Activation condition:** named human approval owners, independent
  security review, defensible residual risk, documented negative tests
  and separate protected PRs. No self-approval by the implementation agent.

## Authoritative technical references

- [Windows named-pipe ACLs](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).
- [Windows named-pipe concepts](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes).
- [Pipe client PID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid).
- [Pipe server PID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid).
- [ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient).
- [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess).
- [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes).
- [age project and format](https://github.com/FiloSottile/age).
