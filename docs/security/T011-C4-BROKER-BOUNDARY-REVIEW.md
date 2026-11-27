# T011-C4 - Out-of-process filesystem broker: security design gate

**Status:** TECHNICAL-DIRECTOR REVIEW RECORDED; BOUNDED NONSHIPPING VALIDATION AUTHORIZED; PRODUCTION NOT ACCEPTED.
**Base:** protected `main` at `a2c660aab9b3268ae525ccd1ccb4b2798318de47` (2026-11-13).
**Scope:** #139, subject to independent #148 and #124 gates. No runtime/service/release grant.
**Canonical inventories:** [filesystem handlers](T011-C-HANDLER-CALLGRAPH-DECISION.md),
[object isolation](T011-HARDLINK-OBJECT-ISOLATION-DECISION.md),
[filesystem boundary](T011-FILESYSTEM-CAPABILITY-BOUNDARY.md).

## Accountable review decision (2026-11-26)

The project owner explicitly authorizes the technical director to perform the
adversarial design review and choose the next bounded implementation. There
is no designated external reviewer; do not invent one or block research on
a fictitious approval. The director's review is not independent external
certification. Independent evidence means actual separately executed kernel
and hosted CI acceptance against the exact candidate, with unchanged negative
controls. Record assumptions, failures, limitations and the release verdict.
The owner retains production-release authority; all #124, #139, #148,
postmerge, provenance and fail-closed requirements remain mandatory.

This decision authorizes the specific hosted AppArmor process-custody
experiment below. It also permits technical design and bounded nonshipping
implementation of the Windows issuer without a nonexistent reviewer.
No production activation, privilege change on a developer host, generic
privileged launcher, or automatic P0 closure is approved.

## 1. Evidence versus implementation

- PRs #318 and #319 are merged. The latter proved a real Linux `nobody`
  UID/GID/PID peer observed through `SO_PEERCRED` on a test-owned socket.
  The test runner, not a provisioned `jdc-authority` process, served that socket.
- `native/authority-service/src/main.rs` still exits with `E_POLICY_UNAVAILABLE`.
  `native/authority-store` documents that pathname-open SQLite transactions
  do not establish protected state custody or full-store rollback prevention.
- Existing MCP file handlers still authorize a pathname before separate
  Node/adapter path I/O. The canonical callgraph lists the actual routes.
- Historical draft #207 proved an isolated Linux issuer read through actual
  system principals and a hosted fixture, but was CLOSED UNMERGED as a
  superseded research stack. Its historical PASS does not apply to this main
  tree, establish anti-rollback, or permit cherry-picking the stack unseen.
- #148's real Windows/Linux hard-link tests disproved outside-object isolation
  in the old capability research. #124's historical N-API lifetime model is
  not approved. Neither issue is resolved by the Linux peer test.

## 2. Decision under review: one independently authenticated broker

The only eligible implementation direction is a separately provisioned,
least-privilege OS process retaining its own policy, anchored root handles,
open file handles, and per-request authorization state. The Node MCP process
must receive only bounded bytes or categorical errors. It must never receive
raw descriptors, unrestricted root handles, a pathname grant, or a reusable
capability token. No file operation may fall back to `validatePath()+fs.*`.

The broker must reject startup when its installed identity, authorized client
principal, protected policy source, revision anti-rollback anchor, or root
custody cannot be proved. Neither a local username nor a self-reported PID,
`rootRef`, environment variable, pipe/socket pathname or CLI flag grants
privilege. A failed bootstrap is not permission to run in the user's context.

**Unresolved legitimate-client bootstrap:** today the portable MCP process
runs with the interactive user's ambient identity, not automatically as a
separately provisioned `jdc-mcp-client`. The installation/launch chain must
prove how a genuine client obtains its protected origin and how another
process under the **same** UID/SID is excluded from reusing it. Matching
Unix UID/GID or a Windows user SID, inspecting a client PID/image name, or
passing a nonce through user-readable configuration is insufficient alone.
No automatic identity switch, privileged wrapper or grant is approved here.

The research-only native N-API object remains excluded. Out-of-process IPC
avoids invoking its unproven ownership mechanism but does **not** close #124.
No production listener, file operation, or installed service is enabled by
this proposal.

## 3. Proposed one-read protocol and operation lifetime

This is an **interface review sketch**, not an executable protocol or an
approval of the values below. No implementation may accept these fields as
authority before an independent design disposition.

| Property | Mandatory behavior |
| --- | --- |
| Envelope | Versioned, canonical, length-bounded framing. Unknown version, malformed, duplicate, partial or trailing frames DENY. |
| Scope | Initial eligible operation is `READ_REGULAR` only; no write, append, create, delete, list, search or metadata delegation. |
| Client identity | Verified from the OS on the accepted IPC connection and bound to the connection lifetime. Caller-provided UID/SID/PID is ignored. |
| Root selection | An opaque ID may *reference* an admin-provisioned root, but cannot create, replace or widen a root. Relative child components only. |
| Policy | The broker owns a protected immutable request snapshot, policy epoch and a proven restart-safe anti-rollback source. Client epoch is a stale-request check, never authority. |
| Replay | Unique operation identity plus an atomic server-side consumed/claimed state; replay, crash ambiguity and store disagreement deny. |
| File custody | Resolve relative to the retained root; open and read only an OS-authorized object with validated storage provenance. No pathname reopen. |
| Response | Bounded byte payload after authorization; otherwise one of `DENIED`, `UNAVAILABLE`, `UNSUPPORTED`, `NOT_FOUND` without sensitive path disclosure. |
| Cancellation | Bounded time/bytes and explicit handle cleanup; cancellation cannot leave a detached authorized task. |

Authentication is not authorization. Linux `SO_PEERCRED` reports credentials
at connection time; it does not prove future custody after descriptor transfer.
A real adversarial test must establish that a transferred/reused connection
cannot gain another principal's authority. Reject ancillary descriptor transfer
or other delegation unless a separately reviewed design can prove it safe.

A policy revocation may be acknowledged only after every old-epoch read
has stopped issuing I/O and sending response bytes, with outstanding streams
closed or finished. Already-transmitted bytes cannot be retracted, even if
still buffered in the OS or retained by a client; a broker-side acknowledgement
is **not** proof of their absence at the receiver. Any stronger no-delivery
claim needs a separately verified client-drain/receipt protocol. Timeout,
crash or uncertain transport state must deny a positive acknowledgement.
New reads require the new epoch. Review and test these linearization points
before activation; never infer revocation safety from a cancelled promise.

## 4. Platform and object-isolation dependencies

**Linux:** the initial disposable proof must run the *server* as the real
independently provisioned `jdc-authority` UID/GID and the client as a distinct
approved `jdc-mcp-client` identity. Verify group custody, parent/socket
ownership/modes, root storage provenance, actual kernel peer credentials,
systemd FD custody if inherited, and no unapproved descriptor delegation.
A root-relative `openat2` resolution proof can establish pathname confinement,
not the stronger hard-link invariant by itself.

**Windows:** an equivalent separately authenticated service/SID and named
pipe require an explicit DACL, exclusive local endpoint, token and process
lifetime checks, and checked `ImpersonateNamedPipeClient` / `RevertToSelf`
semantics. A failed impersonation must abort before touching the filesystem.
No Windows production counterpart is currently approved.

**Windows same-SID DACL falsification (2026-11-16, non-shipping):**
`native/authority-service/tests/windows_same_sid_origin.rs` now exercises
an explicit protected `D:P` security descriptor on a real local,
first-instance named pipe. The ACL grants a data-channel right to the
actual interactive user's SID, plus SYSTEM/Administrators; it does not
grant Everyone/Anonymous. Two separately spawned Windows processes have
different kernel PIDs, each completes a real pipe request, and the server
observes each client's token SID by `ImpersonateNamedPipeClient` after the
read. The RED assumption that this per-user ACL distinguishes genuine
client origin was **falsified**: both processes connect with the same SID.
The final negative-security regression records this fact without logging
the raw SID. This extends #330's default-ACL proof; it does **not**
authenticate a trusted installer/launcher, prove unique client custody, or
grant access to a service-held file.

**Disposition of the tempting SID-only design: REJECTED.** Explicit
Windows DACLs remain necessary to exclude other principals, but are not
a same-principal origin mechanism. Linux user/group socket permissions
have the analogous limitation when the interactive process and a foreign
process share the same UID/GID. Do not accept executable name, command-line
markers, self-reported PID, environment-only secrets or a same-user
restricted token as substitutes for independently protected custody.
Review must identify exactly who creates and owns the authorized client
process/token, the allowed MCP host activation path, how its IPC handles
remain protected from another same-user process, and how installer,
restart, update and uninstall preserve that boundary. Until a positive
authorized-client proof and a true same-principal denial both exist
under a stated OS threat model, retain deny-only native authority.

**Windows same-SID private-handle duplication (2026-11-16, non-shipping):**
The real-process test `native/authority-service/tests/windows_same_sid_handle_dup.rs`
starts one child under the interactive user's actual kernel SID holding an
**unnamed, non-inheritable Windows event handle**. A second, independent child
with the same SID uses `OpenProcess(PROCESS_DUP_HANDLE)` against the first
child, then `DuplicateHandle(DUPLICATE_SAME_ACCESS)` into its own process
and `SetEvent`. The first child receives `WAIT_OBJECT_0` on its original
event. The deliberately incorrect RED assertion that a non-inheritable
handle is protected from another same-SID process failed on real Windows;
the final assertion preserves the observed failure of isolation. No
installed service, broker, root, privileged token or user data is accessed.

**Limits:** The test deliberately communicates the numeric handle value to
the attacker via a test-only environment variable. It proves that a default
same-user process security descriptor can permit a real duplicate-and-use
operation **given that value**, not that an attacker can enumerate any
unknown value or that a separately provisioned, protected process would be
openable. Do not replace a trustworthy client-origin design with a private
handle/inheritance flag under the same interactive token. A candidate design
must independently prove the *process object DACL*, required token privileges,
launch custody and negative `PROCESS_DUP_HANDLE` behavior, including a
legitimate MCP client's positive use path. No production remediation or
credential boundary has yet been approved.

**Windows process-owner WRITE_DAC falsification (2026-11-17, non-shipping):**
The extended `windows_same_sid_handle_dup.rs` now tests a second, stricter
condition. A disposable child assigns its **actual process object** a protected
SDDL DACL allowing SYSTEM full access but only limited-query access to its
interactive user SID. The other separately spawned real same-SID child
disables **all its own token privileges**, checks by independent kernel
queries that the process owner SID equals its token's default owner SID,
and first proves `OpenProcess(PROCESS_DUP_HANDLE)` returns exactly
`ERROR_ACCESS_DENIED`. Despite that denial, `OpenProcess(WRITE_DAC)`
**succeeds**. It then calls `SetKernelObjectSecurity` to grant its own
SID process access, reopens the target with `PROCESS_DUP_HANDLE`, and
`DuplicateHandle`/`SetEvent` signal the original non-inheritable event.
A deliberately false RED assertion that `WRITE_DAC` was also denied
failed only *after* the privilege-isolation and initial-denial controls;
the final real-Windows test passes. No unrelated process is accessed.

**Disposition:** REJECT a same-principal process-object DACL as sufficient
client provenance if the hostile process retains the protected process's
effective owner authority. The initial RED execution under the elevated
host had `SeDebugPrivilege` enabled and did **not** prove the necessary
initial `PROCESS_DUP_HANDLE` denial; it was not scored as security evidence.
The corrected fixture changes **only the disposable attacker child's token**,
not the user's installed runtime or other accounts. This demonstration is
conditional on tested process owner rights and the actual DACL; it does
**not** refute independent protection with a different OS principal,
OWNER RIGHTS rules or a privileged trusted launcher. The test deliberately
supplies the numeric event handle through its own fixture. A positive,
independently protected MCP client path and same-user adversarial denial
remain necessary before granting authority.

**Both:** #148's invariant O forbids reading outside-object bytes through
an in-root hard-link alias as well as changing them. A link-count test, a
path-prefix check and a confined open alone are insufficient. An approved
storage-domain and principal boundary must eliminate unauthorized object
aliasing under the explicit threat model, including preexisting aliases and
concurrent modifications. If the host cannot meet that contract, restricted
read must return `UNSUPPORTED` before disclosing bytes.

Explicit `allowedDirectories: []` retains its existing **unrestricted** legacy
meaning; do not relabel it isolated. A configured restricted policy with a
missing native backend must fail closed, but an all-deny prototype is not a
substitute for proven legitimate in-root reads. Process execution, OpenCode,
URL fetches and delegated search remain separate ambient-authority surfaces.

## 5. Original-host activation decision gate (2026-11-21)

**Disposition: REVIEW REQUESTED; no protected-host implementation or shipping
policy change is approved by this addendum.** This distinguishes a real
original-client origin from the unrelated fact that a process can speak MCP.

### Actual compatibility boundary, not a credential

The existing `setup-claude-server.js` writes `node` or `npx` stdio launch
commands to a user-controlled host configuration. The remote-device adapter
uses the official SDK `StdioClientTransport`, and `src/index.ts` starts the
ordinary stdio MCP server. An independent same-user process can invoke the
same command and advertise the same `clientInfo`: the merged #359 SDK
process test verifies that both complete `tools/list` successfully.
Neither a bundled executable, process name, numeric PID, host config entry,
environment flag, nor SDK handshake authenticates a protected issuer.

An administrative service cannot safely turn an ordinary user-invocable
stdio command into a privileged client merely by wrapping it. A same-principal
intruder can invoke that wrapper too. A launch **under an independently
protected principal and issuer** is a materially different product mode,
not a transparent modification of the current setup contract.

| Candidate host mode | Original-origin guarantee | Proposed restricted authority |
| --- | --- | --- |
| Legacy host, current `node`/`npx` stdio setup | Unproven; same-user SDK impostor admitted to public MCP | **Never grant a native restricted capability on this evidence.** Preserve separate review of legacy ambient tool semantics. |
| Managed/provisioned MCP host and separately protected issuer | Conditionally possible with OS custody proven *before execution* and authenticated throughout the operation | Eligible for a non-shipping one-read prototype **only after reviewer-approved principal, launch and storage models**. |
| User-invocable elevated wrapper, shared secret/config, PID/SID/client-name allowlist | Not an issuer; does not exclude same-user caller | **Rejected** as a privileged admission mechanism. |
| No independently supported original-host activation | No origin attestation | Typed refusal for any *future* restricted native capability; never fallback to ambient pathname I/O. |

**Compatibility consequence requiring product review:** Existing MCP hosts
should still be able to initialize and discover public tools. That capability
must not be presented as protected-file access. Turning on managed mode cannot
silently claim support for arbitrary unmodified hosts. If an operator expects
restricted protected reads from such a host, surface a stable
`E_AUTH_REQUIRED`/`E_POLICY_UNAVAILABLE` classification (mapped to the
reviewed `DENIED`/`UNAVAILABLE` user error taxonomy) rather than asking
users to edit undocumented credentials.
The current code has **not** implemented that end-to-end UX behavior.

### Rust crate / JDC-owned policy alternative — evaluated, not a trust substitute

**Decision for this increment: retain existing crates; DO NOT add an
"OS-independent security" dependency or activate a new privilege path.**
A capability engine inside JDC can limit requests reaching a *trusted* broker,
but cannot stop an unrelated same-UID/SID process from accessing the OS
resources available to that principal or from invoking an unprotected issuer.
This is the distinction between **application authorization** and **external
security boundary**. No cryptographic signing of caller-provided metadata,
unprotected bearer token, shared in-process secret, dynamic library or
memory-safe Rust type establishes original host custody.

Current `main@c8c8e07b5b64f2f37c0265990a35041a06a85df8` already pins:
- `cap-std =4.0.3` inside the **non-shipping deny-only**
  `native/capability-probe` research crate. Directory-relative capability
  operations help avoid ambient path reopening, but cannot prove #148's
  absence of outside-object hard-link aliases. The excluded N-API receiver
  issue #124 must not be reintroduced to make this crate available to Node.
- `rustix =1.1.6` (Linux) inside `native/authority-service` and
  `native/capability-probe`. It provides typed wrappers over kernel
  descriptor/lookup primitives; `openat2` resolution can support namespace
  confinement but cannot authenticate the original host or guarantee that
  every hard link targets an in-root object.
- `windows-sys =0.61.2` in the native authority service provides bindings
  to Windows security/process/file operations. It is **not** a Windows
  equivalent of Linux `openat2`; platform-native tests remain mandatory.

Examined additional candidate families, **not selected as release gates**:
- `wasmtime`/WASI: capability-restricted execution of *guest WebAssembly*
  components can help contain future untrusted plugins **only if all host
  imports are explicitly scoped**. Existing Node MCP handlers and the Rust
  broker are *hosts*, not automatically sandboxed WASM guests; a host-side
  ambient file API or external same-user process bypasses this containment.
  Introducing Wasmtime now would widen the architecture without resolving
  the protected-issuer question.
- `landlock`: meaningful Linux defense-in-depth for restricting a process,
  but is implemented by the **Linux kernel** and does not support Windows.
  It cannot authenticate the original MCP client or prove hard-link
  object provenance. It is not an OS-independent cross-platform answer.
- Application-held MAC/signature/opaque capability: can guard protocol
  integrity **only after** a separately protected key/issuer, authoritative
  policy epoch and recipient are established. If same-user adversaries can
  invoke the signer, copy its keys or use the same OS process authority,
  it cannot supply the missing identity boundary.

**What JDC can implement portably in pure Rust once an issuer is trusted:**
strict request parser and length bounds, immutable operation policy,
opaque non-serializable capability IDs confined to broker memory, typed
denials, resource quotas, explicit operation lifetimes and revocation state.
These are valuable defense-in-depth, not authority to open a new root,
read an out-of-scope object or accept an unauthenticated same-user caller.
Even an in-memory database of grants needs kernel-protected process custody
and a replay-safe durable policy source across restarts.

**Reviewer outcome required before any implementation:** identify the exact
adversary that a proposed crate would stop, demonstrate the enforced OS
principal/storage boundary it still relies upon, and reproduce both a valid
SDK->protected-broker read and a denied second same-principal process on
real Windows and Linux. If this cannot be demonstrated, keep restricted
operations unavailable; do not weaken #148's outside-byte invariant or the
legacy-host compatibility contract.

Official references:
- [cap-std capability directory APIs](https://docs.rs/cap-std/latest/cap_std/fs/struct.Dir.html)
- [rustix openat2 API](https://docs.rs/rustix/latest/rustix/fs/fn.openat2.html)
- [Wasmtime security model](https://docs.wasmtime.dev/security.html)
- [Landlock userspace API](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html)

### Protected bootstrap candidate — testable, not accepted

1. **Provision.** An administrator or independently authorized installer
   establishes a least-privilege service principal, a distinct managed-client
   principal and a protected immutable policy root. Ordinary same-user
   processes must be unable to update the issuer, activation rules or root
   mapping. Review update, rollback and uninstall authority before testing.
2. **Launch.** A protected issuer authenticates the operator/host through a
   separately reviewed OS mechanism, chooses a fixed approved executable
   identity, and creates the managed client. The issuer—not `clientInfo` or
   a JS environment variable—retains trustworthy process or PID-handle
   custody before untrusted code runs.
3. **Windows.** Evaluate an explicitly controlled primary token with
   `CreateProcessAsUserW` and process/thread security descriptors supplied
   at creation. Prove actual privilege prerequisites, OWNER RIGHTS handling,
   deny of `PROCESS_DUP_HANDLE` and `WRITE_DAC` to an independent same-SID
   adversary, restricted handle inheritance, named-pipe impersonation and
   service/client token separation. Existing #358 test custody is a component
   proof, **not a trusted host issuer**. No SCM privilege change is approved.
4. **Linux.** Evaluate a root- or independently protected supervisor issuing
   a client under a distinct OS UID/GID. Retain the kernel `pidfd`; use
   OS-verified issuer credentials, socket custody and per-message writer
   credentials. Explicitly reject transferred descriptors and a second
   process with the same managed-client UID/GID. Preserve the existing
   `linux_peered_read_proof.rs` as a **non-MCP** component proof.
5. **Admit each operation.** The broker accepts only the already-provisioned
   client proven against issuer-held process custody and current policy
   epoch. Connection access is insufficient. Root identifiers are references,
   not grants. Untrusted Node receives no handle, global namespace access,
   credential or reusable admission token.
6. **Revoke and recover.** Define the exact linearization points for read,
   policy change, cancellation, restart and disconnect; hold old-epoch reads
   until securely completed or cancelled before acknowledging revocation.
   Neither a client-side timeout nor a broker crash can imply an operation
   committed or that already-sent bytes were recalled.
7. **Isolate objects.** Prior to a protected byte response, satisfy #148's
   outside-object invariant under approved filesystem/principal boundaries,
   including preexisting/concurrent hard links; #124 must retain exclusion
   of the unsafe N-API receiver. A valid issuer alone never grants content
   access.

### Windows preconnected mutation transport — nonshipping experiment

The current-token local experiment passes a connected, bounded duplex pipe
endpoint to the suspended Node process through an explicit process-creation
handle allowlist; its diagnostics use a separate file. Node does not open the
pipe by name. The endpoint is a channel capability, not a filesystem handle,
global namespace grant, reusable admission credential, or proof of the writer's
SID. The fixed SDK request plan is deliberately not a shipping protocol.

A subsequent real Windows local fixture transfers the preconnected server
endpoint to a separate native service process using an explicit inheritance
allowlist. The issuer retains the exact created client process object, and
passes reduced process references (query-limited-information and synchronize)
for itself and the client. The service validates the inherited handle types,
pipe endpoint, connector process, observed primary-token SIDs and liveness;
original inherited handles are made non-inheritable and remain scoped to the
service subprocess lifetime. The environment numbers only locate inherited
handles and do not authorize a caller. The service alone executes the native
mutation plan and owns its SQLite journal. The issuer verifies exact final
bytes and sequence, including a committed operation whose acknowledgement is
lost. Both fixtures use the current token; separate processes are not distinct
security principals. The local CI gate is a prerequisite, not an admission
or anti-delegation proof.

This experiment does not revise the approved admission contract above.
A distinct protected issuer must still establish primary-token provenance,
same-session creation, service-side handle custody and independently verified
attacker denial. The local default pipe DACL and same-token fixture cannot
establish those properties. A retained process handle alone cannot establish
per-message writer identity or prevent an intentionally cooperating issued
client from forwarding its capability. Any production delegation policy or
change to the earlier no-handle requirement needs independent approval.
The hosted NTFS admission and outside-object integrity gates remain mandatory.

#### Required Windows issuer environment preflight (nonrelease)

Before treating the hosted issuer as eligible to launch independent primary
tokens, the existing NTFS acceptance harness now explicitly executes native
observations under the service, client and attacker credentials. Their actual
TokenUser and TokenOwner must match the independently provisioned role, all
four SIDs must differ, the primary token session must match the issuer,
integrity must be medium, and administrator/SYSTEM membership and the
fixture's prohibited privilege inventory must be absent (not merely disabled).
This is a deliberately conservative disposable-fixture contract, not a
production token allowlist.

The issuer is observed separately with its own token, using the bounded native
TokenPrivileges inventory and exact locally resolved LUIDs for
SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege. The gate requires
both privileges to be present; their presence alone is not proof of successful
CreateProcessAsUserW or protected custody. The fixture does not enable or
assign privileges, change session IDs, or attempt a less constrained fallback.
On the local Windows validation host the former privilege is absent; the
latter is present but disabled (session 0). The ordinary storage-domain
verdict remains scoped to the original storage proof; the independent issuer
prerequisite has its own mandatory marker and failure path. Hosted execution
is still required, and neither successful prerequisite observation nor the
local same-token handoff replaces the actual cross-principal SDK-to-NTFS
mutation acceptance.

#### Windows distinct SCM principal observation (nonrelease)

The native job on `e13322027b37443102859a48eb0ec7f6191f6b7b`
(run 45933296360, Windows job 140290627251) again rejected the old
CreateProcessAsUserW prerequisite. Do not grant SeAssignPrimaryTokenPrivilege,
SeIncreaseQuotaPrivilege or SeDebugPrivilege to an interactive issuer.

The next bounded SCM experiment provisions the fixed authority and issuer
virtual accounts independently, using restricted service SIDs, protected
service-object DACLs and a RequiredPrivileges list limited to the traversal
privilege. Actual token inspection requires the correct role, primary token,
restricted SID, no elevated group, and no other privilege even disabled.
The issuer creates and retains a suspended child under its own primary
token with process and thread DACLs applied at creation. The only additional
observer ACE is PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE for the
fixed authority SID on the process, never the thread. Before child issuance
the issuer also limits its own process DACL; SCM creation itself is under
trusted administrative provisioning, not a proof against pre-existing
same-account handles.

A disposable protected rendezvous file identifies the two live kernel process
objects by PID and creation time. The observer resolves the fixed SCM service,
matches its live process identity, opens only the reduced process handles,
rejects a stale creation stamp and requires exact access-denied results for
handle duplication, memory access, termination, thread manipulation and ACL
mutation. The issuer, not the independent observer, checks the actual primary
token of its child using the original handle. Microsoft documents separate
token-object access checks and a cross-account privilege limitation for
OpenProcessToken; the observer must not receive debug privilege.
The fixture verifies the observer cannot write the rendezvous file and
requires explicit terminal cleanup of the suspended child and both services.

This is a kernel-object observation experiment, not a production attestation
protocol: the file is only a test rendezvous protected by administrative
provisioning, not a durable or authenticated MCP grant. The trusted issuer's
RUNNING state denotes test readiness only; the separate deny-only SCM binary
is unchanged. No Node child or mutation is executed by this experiment.
Hosted positive and negative results are still required before integrating
the preconnected SDK channel, admitted NTFS journal and cancellation with
these principals. Existing storage and issuer prerequisite gates stay
mandatory; the new proof cannot replace them on the strength of a local
unit-test result.

References:
<https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights>,
<https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes>,
<https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken>.

#### Windows request cancellation at the native publication fence (nonrelease)

The local same-token SDK fixture now exercises actual MCP cancellation after
native staging. Windows libuv duplicates the inherited standard descriptor
when opening a pipe and does not close that original descriptor when the
socket is destroyed. A timeout is therefore not evidence of peer closure.
The forwarded MCP abort sends an explicit cancellation frame through the
issuer-connected channel; the native service requires that exact frame,
disconnects its endpoint, and verifies that publication is no longer
admissible while the issued process remains alive.

The proof requires the rejected journal sequence and digest, absent destination
and stage, unchanged outside sentinel, rejected replay after reopening the
journal, and no SDK resubmission. Its terminal synchronization uses a separate
test-only channel with native peer verification. The positive Windows SDK
paths also check the pipe state at the publication fence; this observation
does not make later disconnection atomic with a filesystem rename.

The local cancellation and positive inherited-channel cases are mandatory
native CI checks. This evidence does not establish distinct-principal SCM
custody, hosted NTFS acceptance, or release readiness.

#### Linux request cancellation at the native publication fence (nonrelease)

An actual local SDK cancellation after staging (not process termination) is
now exercised with the issued process kept alive until the native service
reports a terminal journal verdict. Process liveness alone was insufficient:
the original test path could commit after the SDK closed its request socket.
The Linux SDK mutation fixture now requires an idle, live request connection
at the publication fence, rejecting EOF, half-close, unexpected pending data
or a socket observation error. The actual staged cancellation must record
Rejected with the expected sequence/digest, remove the stage, preserve the
outside sentinel, and leave no destination object or retry. This is one
commit-time observation, not an asynchronous revocation acknowledgement or a
promise that a disconnect after commit admission can undo a kernel rename.
The regular six-request SDK plan and the local cancellation case are separate
mandatory CI checks before admitted-mount acceptance. The hosted harness also
requires a fresh root-issued SDK child on the same admitted journal, advancing
sequence 10 to a rejected sequence 11 without altering final.txt or the outside
sentinel. On candidate `64c869ac82f9ae437dfbe265cb12f386111f0935`, GitHub
Actions run 45902743027, Linux job 140192174194, completed successfully and
emitted `T011_STORAGE_LINUX_DOMAIN_PASS_NONRELEASE`, including the root-issued
SDK cancellation and distinct-peer rejection markers. This is hosted fixture
evidence, not production acceptance. Windows job 140192173828 failed during
positive NTFS admission before the first journaled mutation. Windows
cancellation/authority claims remain independently gated.

Follow-up candidate `ed3deaa1c6cac3d126aa3925f04668ac6ac26932` (run
45906663715) identified `FindFirstVolumeMountPointW` returning Win32 error 5
under the actual dedicated service account. Do not grant storage management
privileges to the service and do not interpret that error as an empty volume.
The experimental replacement enumerates local volume GUIDs and obtains each
volume's complete DOS access-path inventory using `FindFirstVolumeW`,
`FindNextVolumeW` and `GetVolumePathNamesForVolumeNameW`. See Microsoft Learn:
<https://learn.microsoft.com/en-us/windows/win32/fileio/displaying-volume-paths>.
The admitted volume must occur exactly once with only its expected drive root;
no other volume may list a mount below that root. Unknown, incomplete or
malformed inventories deny admission. This is an observation under the trusted
issuer's namespace/topology assumption, not a globally atomic mount-manager
transaction. The hosted experiment must prove the actual dedicated-token
positive and both incoming and outgoing mount negatives with unchanged
journal bytes, exact denial reasons, and successful readmission after removal.
No real mount transition is performed on a developer workstation.

Candidate `6b21c83d0ce143149a3ad9c4b18bbef3a9a38473`, hosted native run
45918855692, Windows job 140244473887, emitted
`T011_WINDOWS_ADMITTED_JOURNALED_MUTATIONS_PASS_NONRELEASE` under the dedicated
service account. The following active-owner mount transition failed, and
cleanup masked the primary failure with alias-removal/VHD-state errors.
Linux native job 140244474082 passed. The Windows test issuer now uses the
Storage provider's partition access-path cmdlets, checks exact GUID and path
ownership before removal, confirms absence and rejects unknown reparse points.
It retains the primary failure independently of cleanup, and never detaches
or recursively removes an unverified topology. This fixture correction is
not evidence that either hosted mount transition has passed yet.

#### Linux post-exec SDK process custody (technical decision, nonrelease)

The native Rust client's non-dumpable state cannot be assumed to survive
exec of Node. Yama scope 1 alone does not deny every ptrace READ-mode check.
Candidate `4e034f25bc02caf2bbbbd1c7c0367e84c41b0a6b`, native run
45931757252, Linux job 140285739378, failed the same-UID inspector with
`E_PEER_SDK_INSPECTION_NOT_DENIED` despite the target profile being enforced.
AppArmor's kernel tracee check can be skipped for an unconfined tracer.
The profile is retained as defense in depth, not the process custody boundary.

The selected replacement experiment creates a fresh user namespace in a
single-threaded root fixture process before dropping credentials. Its
privileged parent pins that namespace, checks root ownership and its exact
parent namespace through nsfs ioctls, and writes only the one-ID UID and
GID maps. The child clears supplementary groups, sets all real/effective/
saved IDs to the dedicated account, sets no-new-privileges, and execs the
root-owned byte-verified Node image without an intermediate shell. A private
socketpair synchronizes namespace creation, mapping, Node readiness and
release. The issuer verifies the namespace identity and maps, actual Node
image, credential fields, empty capabilities and enforced AppArmor label
before attesting the live pidfd. No UID 0 mapping is introduced.
The Node fixture cannot request broker I/O before the issuer releases it.

A separate lightweight kernel experiment with ordinary Node processes
verified all five inspection denials against the root-created namespace,
with positive READ controls against an ordinary same-UID/GID process.
That experiment does not substitute for the hosted SDK acceptance.
Candidate `fb041f669427cf33cbcfe82fd1e94fcdef0db078` subsequently passed
the actual hosted Linux native job 140296781765 (run 45935227835), including
the mandatory protected SDK read, journaled mutations and staged cancellation
gates, and emitted `T011_STORAGE_LINUX_DOMAIN_PASS_NONRELEASE`. The Windows
job 140296781554 passed local SDK cancellation, separate-process handoff and
admitted NTFS mutations, but failed the old distinct issuer prerequisite.
This is scoped nonrelease evidence, not production acceptance.
References: Linux kernel `security/commoncap.c` and
`security/apparmor/task.c`, user_namespaces(7), ioctl_nsfs(2).

A real, explicitly unconfined second process under the dedicated client
UID/GID must pass procfs READ-mode controls against a live ordinary same-UID process, then receive
only EACCES/EPERM for the issued Node executable link, descriptor link,
maps/mem opens and pidfd_getfd. Missing objects, exited processes and
unsupported syscalls fail the test. No protected bytes are read or printed
by the negative probe. Keep the target pidfd alive, observe its enforced
label before and after inspection, and only then attest. Require this
verdict for SDK read, journaled mutations and cancellation, retaining
existing legitimate operation, same-UID/foreign-peer and outside-byte
controls. No global Yama/sysctl changes. Remove only the unique profile
after preventing new fixture image launches and establishing that the
dedicated UID has no remaining processes; otherwise retain the fixture
and fail the disposable job. Never load this profile on developer hosts.

This is an experiment for the Ubuntu hosted target, not a claim of portable
production MAC availability, protection from a trusted administrator, all
possible process inspection interfaces, signal denial, or mutable client
state integrity. Actual hosted profile enforcement and negative/positive
controls are required before calling the experiment successful. Unsupported
hosts must deny rather than use a weaker runtime. References:
<https://manpages.ubuntu.com/manpages/noble/man5/apparmor.d.5.html>,
<https://manpages.ubuntu.com/manpages/noble/man8/apparmor_parser.8.html>,
<https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html>.

#### Linux SDK state custody (nonrelease, hosted verdict pending)

The issued SDK previously used a writable host directory shared by processes
of the dedicated client UID. Process inspection denial alone does not
protect that directory. The root fixture now creates a fresh mount namespace,
makes propagation recursively private, and mounts a bounded tmpfs (16 MiB,
4096 inodes, nosuid/nodev/noexec) at the root-owned empty state mountpoint
before entering the root-created user namespace and dropping credentials.
The issuer pins the mount namespace and checks its owning user namespace.
The actual SDK must exclusively create a fixed, non-secret state canary before
readiness. The issuer checks the real filesystem type, device, owner, mode,
mount flags, file identity and exact bytes, then repeats the checks after
a separate unconfined same-UID process attempts read/write opens through
both the host path and the SDK's procfs root. The ordinary same-UID control
must still traverse its target's procfs root. No request is attested until
these checks pass. Read, mutations and staged cancellation each require a
fresh private state verdict; the host state must remain empty and unmounted
afterward. Cleanup refuses recursive deletion through a visible state mount.

This only isolates ephemeral fixture client state. It does not establish
durable policy custody, prevent denial-of-service signals, or authorize
production deployment. The actual hosted kernel acceptance remains mandatory.

The disposable Windows token observations are isolated in a private
`cfg(test)` child module. The SCM observer retains its no-output contract;
fixture outputs are fixed verdict markers only, not SID, session or privilege
inventories. Neither an issuer preflight nor a marker grants launch authority.

### Mandatory decision experiment

The **next non-shipping functional increment**, under a recorded technical
decision for its issuer/principal model, is an official SDK MCP session under a
*real* issued managed-client process, with one broker-held regular-file read
and exact output bytes. Its negative controls must independently demonstrate:

- A different same-interactive-user launcher cannot request protected
  activation, reuse an issued client, or duplicate its held channel.
- A separate process under the *managed-client* OS principal cannot reuse
  the issuer-attested origin or delegate a socket/pipe.
- Stale, replayed or revoked requests yield typed denial without leaking
  response bytes; service unavailable yields typed unavailability.
- Symlink/junction, final-component rename, preexisting hard-link alias and
  concurrent namespace changes never read or alter outside-object bytes.
- An unmodified legacy host retains documented public MCP compatibility but
  **cannot** receive a privileged native read by merely copying metadata
  or launch configuration.

Test both Windows and Linux real kernel principals, not mocks. Verify actual
attack setup, before/after outside bytes and signed package provenance.
Do **not** create another speculative SDK identity test or promote a
user-invocable privileged launcher. A positive response is release-blocked
until the complete #139/#148/#124 criteria, review and production packaging
are independently satisfied.

**Review questions requiring explicit sign-off:** Which supported hosts may
enter managed mode and by what authorized installation action? What precisely
authenticates the original host *before* issuing it a protected process? Who
owns each OS principal and protected policy source? What is the product
contract for legacy hosts with configured `allowedDirectories`? Which
privileges, IPC rights and filesystem boundaries are reviewed on both OSs?
What exact revocation and rollback evidence is required?

## 6. Acceptance sequence and review decision record

1. The technical director must decide supported storage/volume/mount models,
   service/client principals, IPC custody, anti-rollback mechanism and the
   exact object-origin invariant; record concrete approval or rejection and
   independently executed acceptance evidence.
2. Preserve the original hard-link and namespace-swap RED evidence. On real
   disposable Linux, prove an actual `jdc-authority` server serves one valid
   bounded read, rejects a foreign client, stale/replayed/revoked operations,
   symlink, final-component swap and hard-link alias, and verifies exact
   outside-sentinel bytes. Attack setup must itself be confirmed.
3. Verify restart, cancellation and concurrent revoke versus read. No
   response after acknowledged revocation; no leaked handles or plaintext
   on failed requests. The test must exercise the actual compiled broker.
4. Repeat corresponding proofs on real Windows under an actual service
   identity. Do not infer Windows parity from Linux or from a service-token
   observer that performs no filesystem operation.
5. Only then propose a *separate reviewed* production integration covering
   the canonical handler callgraph and in-memory document processors, with
   official MCP SDK tests on independently extracted Windows/Linux packages.
   Preserve all existing T008-T010 semantics and tool error contracts.
6. Require exact-head mandatory CI, native acceptance, CodeQL, governance,
   installers and independently checked postmerge `main`. Never bypass the
   existing production isolation gate to make research code reachable.

**Open technical decisions:** Which operator owns immutable roots? Which
filesystems and external aliases are permitted? What OS-protected monotonic
state survives rollback/reinstall? How is the actual interactive-user MCP
launched as a verified client without granting access to another same-UID/SID
process? How are transferred descriptors excluded? How are previously sent
bytes distinguished from revocation-acknowledged future sends? What evidence
proves Windows named-pipe parity?

**Disposition:** BOUNDED NONSHIPPING EXPERIMENT AUTHORIZED BY TECHNICAL
DIRECTOR; EXACT-HOST EVIDENCE REQUIRED; NO PRODUCTION IMPLEMENTATION OR
RELEASE PERMISSION. The current `main` continues deny-only for the native
authority; #124, #139 and #148 remain P0. `releaseEligible:false` and
production NO-GO remain.

## Official primitive references

- [Linux Unix-domain peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html)
- [Linux anchored path resolution](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [Windows named-pipe client impersonation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [Windows named-pipe access control](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Windows process token and access control](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Windows DuplicateHandle API](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [Windows OpenProcess API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
- [Windows owner of a new object](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object)
- [Windows standard access rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights)
- [Windows process creation and explicit handle inheritance](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-processes)
- [Windows hard links and junctions](https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions)
- [Windows CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [MCP TypeScript SDK v1 client transport](https://ts.sdk.modelcontextprotocol.io/client.html)
