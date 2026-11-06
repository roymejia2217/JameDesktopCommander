# Local tunnel administration and credential recovery — contract proposal

**Status:** design-only; no runtime implementation, authorization grant, service installation, or release approval.  
**Tracking:** #248. Dependencies/related boundaries: #96, #98, #150, #32; security release gates #124, #139, #148.  
**Targets:** Windows installer (`.exe`), Linux installer (`.deb`), with equivalent headless Linux CLI for basic management.

## Problem demonstrated

A real operator incident on 2026-11-03 combined all of the following: the Windows Scheduled Task was running; the official tunnel-client process had an established outbound connection; local `/healthz` and `/readyz` returned 200; the official *component* health disclosed control-plane HTTP 401 and sustained authentication failures; MCP stdio initialize/tools-list had not been observed; remote ChatGPT calls failed with client-facing 404/429. The dedicated runtime API key had expired. Replacing the secret in a local protected file and restarting the installed tunnel task restored fresh ChatGPT MCP operations.

**Invariant:** process/task liveness, TCP connectivity and local readiness must never be displayed as proof that authenticated control-plane polling or fresh MCP tool delivery works. A remote-visible 404/429 is not sufficient to classify the independent HTTP 401. A 401 proves credentials were rejected, **not** why; claim an expiration only with independently authenticated provider metadata or a trusted stored expiry date. A successful `doctor` config check does not validate remote credential acceptance.

The incident details are intentionally sanitized: no usernames, exact host paths, profile IDs, private URLs, key IDs, credentials or process IDs belong in this public design or support exports.

## Verified existing integration surface

| Current component | Baseline behavior and explicitly noted S1 candidate | Missing operator guarantee |
| --- | --- | --- |
| `src/npm-scripts/tunnel.ts` | Windows tunnel command dispatch, native task lifecycle, status, diagnose and events | No credential rotation or local management UI |
| `src/platform/windows/tunnel-functional-diagnostics.ts` | Bounded loopback-only read of official admin `/health?details=true`; typed control-plane HTTP causes already merged in #249; S1 candidate additionally derives a sanitized local operability assessment | No verified fresh MCP remote request and no local credential-recovery UI |
| `docs/WINDOWS-TUNNEL-RECOVERY-FENCING.md` | Pure recovery preflight; **non-operational** and not an authority token | No OS-enforced privileged recovery executor |
| `src/platform/linux/tunnel-lifecycle.ts` / `docs/LINUX-TUNNEL-LIFECYCLE.md` | Development-only managed `systemd --user` lifecycle, official-client preflight and status; deliberately stopped state preserved | No shipped local control UI, no credential-rotation path or real authenticated remote E2E |
| `docs/DISTRIBUTION-CANDIDATE.md` | Portable **unpublished** test candidates, `releaseEligible:false` | Not a signed Windows `.exe` / Linux `.deb` local-management distribution |

The installed third-party tunnel-client, existing UI bridge and OpenCode gateway are **separate components**. Installation-specific service paths and secret stores remain outside Git. UI Bridge presence is *not* authorization to control the tunnel or read secrets.

## Target public status contract (partially implemented)

### Implemented S1 local observation subset (read-only)

`src/platform/tunnel-local-operability.ts` defines a portable, pure local assessment of the official client's sanitized component observations. The Windows `tunnel diagnose` parser exposes `operability` with `kind: local_operability_v1`, `state`, `reasonCode` and `remoteRoundTrip: not_observed`. The only possible local-only states are `degraded` and `unverified`; this interface **cannot** assert remote MCP availability or authorize service control.

The classifier distinguishes active 401/403/429/5xx failures, missing control-plane evidence, absent handshake/discovery, and local readiness. HTTP-denial classification requires a degraded official control-plane component, `http_error` reason and a positive validated consecutive-failure count. A confirmed local readiness failure remains `degraded` even if control-plane diagnostics are unavailable; an unknown control plane cannot hide it. A missing counter, stale HTTP code, missing live/ready flag, or apparently green local probes never become a remotely healthy claim. The results contain allowlisted codes, not raw provider errors, tool names or secrets. A 401 is **rejected credentials**, not independently confirmed expiry. The shared `tunnel diagnose` response additionally provides static, secret-free `operatorGuidance` for verified 401 (review the official provider credential), 403 (review account/profile permissions) and 429 (respect rate limits without restart storms); missing/stale/unsupported evidence returns `null`. These messages do not read, rotate or authorize changes to credentials.

### Read-only credential reference classification (S2 preflight only)

The current Windows task-registration status and Linux active-unit status reuse their existing provider-profile reads to expose a **sanitized source kind**: `file_reference`, `environment_reference`, `unsupported`, or `unverified`. The classifier follows the official `control_plane.api_key` `file:` / `env:` reference syntax without exposing the actual secret, reference path, environment variable name or raw profile text. Non-local/relative file references, literal keys and malformed reference syntax are unsupported; absent or unavailable evidence stays unverified. An inactive Linux unit does not read the profile and reports unverified. These categories describe **syntax only**, not file existence, ACL/owner custody, active credential identity, authorization for write, successful provider authentication or rotation eligibility. The new Linux-only `tunnel credential-check` action performs an additional **read-only, point-in-time custody check** for the file referenced by the installed, exact-template `systemd --user` unit's official selected profile. It verifies the current OS UID, regular non-symlink opened file, exactly mode 0600, a single hard link, a bounded size and canonical protected directory ancestry. The result contains only a sanitized source/custody classification with `rotationAuthorized: false` and `remoteAuthentication: not_checked`. Unsupported `env:` sources remain unverified for file custody. A checked inode does not confer write authority or future same-UID race protection. No corresponding Windows ACL proof is implemented. JDC does **not** read the credential bytes, replace the live key or restart a tunnel as part of this slice.

The Linux status surface additionally exposes `lifecycleObservation` from a portable, read-only evaluation of the already parsed systemd activation state and official-client aggregate health. It reports `inactive` without inventing deliberate operator intent, and otherwise uses `unverified` reason codes for a disabled unit, missing control-plane polling, missing local health, inconsistent evidence or absent fresh remote delivery. It cannot diagnose HTTP 401 or prove a remote MCP round trip; it never changes service state. The existing `active`, `enabled`, `healthy` and `controlPlanePoll` fields, as well as Linux exit-code behavior, remain unchanged.

The remaining unified cross-platform snapshot, verified service intent, real operator identity, freshness timestamps, signed local controller, secure rotation, UI, packaged lifecycle and authenticated fresh remote round-trip are **not implemented by these S1 increments**. No installed service/runtime is modified.

### Remaining target public contract

A shared, versioned operations core produces **sanitized** observations; platform adapters supply typed evidence. A UI must never infer a stronger state than the evidence.

```text
LocalTunnelSnapshotV1:
  observedAtUtc            trusted observation time, with unknown on clock failure
  lifecycleIntent          running | stopped | unknown
  taskState                running | stopped | missing | unknown
  clientProcess            running | absent | unknown
  localReadiness           ready | not_ready | unknown
  controlPlane             authenticated | rejected_401 | forbidden_403 |
                           rate_limited_429 | transport_unreachable |
                           server_error | unobserved | unknown
  mcpInitialize            observed | failed | not_observed | unknown
  mcpToolsList              observed_complete | observed_incomplete |
                           not_observed | unknown
  remoteRoundTrip           verified_fresh | failed | not_observed | unknown
  reasonCode               one allowlisted typed reason; no raw server message
  remediationHint          localized, safe instruction based on evidence
  provenance               source, bounded age and trusted-vs-unknown classification
```

Status precedence: explicit intentional stop is not a crash and is never automatically undone. Authenticated control-plane failure is **degraded** even when local health is ready. Unobserved/aged evidence is **unknown**; do not render it as healthy. `verified_fresh` requires a bounded round trip on the correct registered tunnel and requested MCP target, with an independently proven request/result pair; a past `tools_list` observation is not fresh tool execution.

Typed diagnostics must distinguish at least `CONTROL_PLANE_CREDENTIAL_REJECTED`, `CONTROL_PLANE_FORBIDDEN`, `CONTROL_PLANE_RATE_LIMITED` (honor bounded Retry-After), `CONTROL_PLANE_UNREACHABLE`, `MCP_HANDSHAKE_UNOBSERVED`, `REMOTE_DELIVERY_UNOBSERVED`, `SERVICE_STOPPED_BY_OPERATOR`, `PROFILE_INVALID`, `SERVICE_IDENTITY_UNVERIFIED`, and `CLIENT_VERSION_UNVERIFIED`. If provider expiry metadata exists, distinguish `CREDENTIAL_EXPIRED_CONFIRMED` from a generic 401. No noisy retry loops.

## Local authority and UX boundary

The management surface must remain independently accessible while remote ChatGPT/MCP and the provider control plane are unavailable. The first implementation should prefer an authenticated native local operator application plus a reusable backend/CLI; a local web UI is an *optional* presentation route subject to a separate threat review. Binding HTTP to loopback does **not** authenticate browser callers; absent OS-backed peer authentication, per-session anti-CSRF/origin protection and explicit authorization, all mutations fail closed. Never publish the management port to LAN/WAN or bind to all interfaces by default.

Read-only health/status must not imply permission to start/stop services or change credentials. Mutations require an authenticated OS operator with a narrowly scoped, independent local authority; existing Windows Task Scheduler/SCM and Linux `systemd --user` boundaries remain enforced. No new privileged service or generic administrative shell is authorized by this document. Preserve a durable intentional `stopped` state, require verified task/unit identity, prevent duplicate control instances, serialize mutations through an OS-backed mechanism, and re-check authority at the side-effect boundary. A pure preflight approval does not authorize execution.

## Credential rotation contract (not implemented)

The provider issues runtime keys; JDC does not autonomously mint them unless an independently reviewed official delegated issuance mechanism exists. An operator can paste a replacement key into a protected one-time input, choose the currently installed *registered* tunnel (not an arbitrary file path), validate the expected organization/project and required scope through supported provider facilities, and request an explicit rotation.

The installed profile's schema must be interpreted with a supported parser: provider profiles may contain JSON syntax in a `.yaml` file, with `control_plane.api_key` referencing `file:` or `env:`. No regex-based key discovery and no arbitrary target `file:` path accepted from the browser. Support a clearly typed **unsupported** outcome for secret sources that cannot be safely rotated.

A reviewed platform adapter must verify secret ownership, file type, parent custody, ACL/mode and target instance before mutation; stage a restrictive new credential atomically, protect write/durability across crashes, avoid retaining an unencrypted old secret in backups, perform a single fenced service handover, and verify actual authenticated control-plane polling before declaring success. If activation fails, report degraded, preserve the operator's desired state and provide a bounded safe rollback/retry path; expired old credentials cannot be described as healthy rollback. Exactly what rollback can restore is recorded, not guessed.

Never echo, log, persist in UI state, place in environment dumps, command arguments, URLs, telemetry or support bundles any credential or bearer value. Zero ephemeral buffers where runtime capabilities permit; do not claim complete memory erasure. Provider link targets and any external data are untrusted inputs unless allowlisted. Avoid clipboard handling unless clearly user-authorized.

### S2 transaction coordinator — internal contract, no write adapter yet

`src/platform/tunnel-credential-transaction.ts` defines an **inert**,
dependency-injected rotation coordinator with versioned, allowlisted
`local_credential_rotation_v1` receipts. It does not expose a new CLI command,
web handler, MCP tool, OS filesystem writer or network endpoint. Merely
implementing its TypeScript interface does **not** provide authorization.

The only legal transition towards a successful receipt is:

1. Consume the operator's one-time byte buffer and reject invalid control
   characters before the first asynchronous operation; promptly zero the
   caller-owned and staging buffers (best-effort only in a managed runtime).
2. Acquire an OS-authenticated **exclusive transaction lease** from the local
   adapter and verify that the exact registered service/credential generation
   still belongs to the authorized operator and is intentionally running.
3. Stage the candidate in the verified storage namespace with restrictive
   metadata and durable writes; never use a caller-selected arbitrary path.
4. Recheck registration and fencing epoch while atomically publishing. If
   an operator STOP, identity mismatch or concurrent write is detected, deny.
5. Activate **conditionally**, without reviving a deliberately stopped service.
6. Verify **fresh official control-plane authentication**, not local TCP,
   readiness, cached health or the existence of a process.
7. Finalize the durable transaction only after the authenticated provider
   check. Never confuse it with a fresh ChatGPT MCP request/result.

A failure after staging requests safe restoration from the **OS adapter**.
The adapter must guard restoration against lost updates and intentional STOP,
and must durably reconcile pending work after process crash or power loss.
`prior_credential_restored_unverified` means only that the previous *file
state* was restored; its provider authentication may still be expired/rejected.
`recovery_required` means that cleanup, finalization, or lock release cannot
be trusted. A completed control-plane authentication receipt always includes
`remoteRoundTrip: not_observed`. No raw exception, secret, path, provider
message, or credential identifier is part of a public receipt.

**No live storage adapter is present yet.** The coordinator contracts alone
do not prove crash-safe file replacement, operator SID/UID custody, locked
generation, service fencing, or provider authentication. Linux
`credential-check` remains a read-only point-in-time observation.
Windows requires an authenticated process token SID, the actual Task Scheduler
principal, file and parent ACL verification, and an explicit decision about
the supported Win32 replacement/backup protocol. The existing
`windows-atomic-replace.ts` helper has fallbacks intended for ordinary
state files and **is not approved** for secret rotation.

### Native Linux atomic file-transaction engine (experimental; non-shipping)

The isolated `native/tunnel-local-rotation` Rust crate implements an actual
**disposable-file filesystem transaction** using OS-native primitives:
private directory descriptors and `openat` with `O_NOFOLLOW`, owner/mode/link
checks, the stable Rust exclusive file lock, mode-0600 staging and file fsync,
a durable metadata-only journal bound to the exact original filename and
inode identities, Linux `renameat2(RENAME_EXCHANGE)` for an
atomic old/new inode swap, parent-directory fsync, and explicit
`publish`/`rollback`/`confirm`/`recover_local_file` methods. The journal
distinguishes creating, prepared and durably committed phases. Recovering a
published but uncommitted state restores the original inode; recovering a
durably committed state retains the replacement and cleans remaining stage
artifacts. Every outcome remains **provider-unverified** until the separately
authorized service layer proves fresh authenticated polling.

This crate is NOT wired to a JDC CLI, UI, MCP tool, Windows service, existing
protected authority service or an installed tunnel. The test suite operates
only inside disposable, nonproduction directories and **must pass**
real hosted Linux CI before the crate is accepted. **No standalone invocation of this crate grants authority**:
the caller must still prove the selected installed tunnel's effective
credential source, OS principal, profile ancestry, desired-state generation
and local operator authorization independently. Linux file locks are advisory
against uncooperative processes sharing the same UID; a verified directory
handle cannot prevent all same-UID namespace replacement around the running
provider. The Linux kernel/filesystem must support `RENAME_EXCHANGE` or the
operation fails closed. The old secret inode temporarily exists under a
private staging name until a successful commit or explicit recovery; this is
not a durable provider-issued credential vault, and power-loss residue must
be reconciled before any new rotation. Tests include actual child process
exit without destructors and interruption-state reconstruction; they do
**not** simulate power removal from storage hardware or prove device fsync
honesty. A corrupted or ambiguous journal must fail closed and require
explicit manual investigation, never guess an old or new key. Storage hardware
may preserve deleted sectors: no secure erase or complete memory erasure is
claimed.

Windows needs an independently audited SID/ACL and Win32 transaction adapter.
Neither this crate nor the TypeScript coordinator completes the installed
cross-platform S2 backend or authorizes displaying an active Rotate button
in egui.

### Frontend boundary (future Rust + egui)

Prefer a native local operator control panel backed by the *same reviewed
OS-specific transaction adapter* as a headless CLI. The panel must remain
available without ChatGPT/MCP. An egui password text field can mask entry,
but is not a credential vault: do not persist its text, show it in logs,
include it in command arguments, prefill it from the existing secret file,
or present a clipboard-derived value without deliberate user action.
Use a single explicit confirmation for the currently installed service and
display distinct steps: authorized, staged, published, reactivated, verified,
confirmed; on failure, display a sanitized reason and whether restoration is
verified or a manual recovery is required. Show service lifecycle, authenticated
provider control plane, and fresh MCP delivery as separate indicators.
Prefer a shell-free child process of the **installed, version-matched local
CLI** with a one-shot secret sent only through a bounded private stdin pipe,
then accept only the typed sanitized receipt on stdout. Do not pass the key
in argv, environment variables, URLs, IPC endpoints, or persisted UI state.
This transport still needs a separate operator/session and package-provenance
review; it is **not implemented** by the coordinator. No listener or remote
MCP route may invoke the transaction backend.

## Installer and failure-recovery requirements

Windows `.exe` and Linux `.deb` must ship the approved local management capability and verify release signatures, provenance, dependency/ABI compatibility, installed target identity and supported client versions. Upgrades migrate only authorized state; uninstall/rollback must leave an intentional stop intact, not leak secrets or orphan an uncontrollable task/unit. Linux operation must work through the audited CLI when no graphical session is available. UI must present component-by-component status, action-specific confirmation, copyable *sanitized* incident report and accessible keyboard/navigation states.

The operator UI distinguishes network-offline, DNS failure, invalid credential, 403 scope problem, 429/Retry-After, MCP-child unavailable, remote route unobserved, OS permission denial, and intentionally stopped service. Display a recovery path that names the affected component rather than generic "connection failed." Warn before expiry only when the date and provenance are known; never store an inferred expiry as a fact.

## TDD and release acceptance — required before operational implementation

| Test layer | Required failure / positive controls |
| --- | --- |
| Pure state/diagnostic tests | RED then GREEN for running+ready+401 being degraded; 401 with unknown expiry not called expired; 403, 429, unknown, delayed/stale observations; deliberate STOP wins over retry |
| Secret-store component | Wrong principal, malicious path/symlink/reparse, untrusted parent, mode/ACL mismatch, lost update, malformed JSON-in-YAML, concurrent rotation, crash/atomicity, failed key verification, secret redaction |
| Service adapter integration | Verify native Windows Task Scheduler/SCM or Linux user-systemd state, fenced single-owner action, offline boot, restored network, duplicate worker rejection and intentional STOP |
| Local UI / API security | Unauthorized browser/OS principal, CSRF, Origin bypass, stolen/stale session, misrouted profile, no secret in logs/export; keyboard/screen-reader critical path |
| Real packaged E2E | Fresh installer and upgrade/rollback on Windows and Linux; synthetic expired-key outage via controlled credentials, official tunnel-client status, operator rotation, *fresh actual ChatGPT MCP round trip* and negative failure assertions |

No test output from a mock, synthetic client, or process `Running` state can substitute for genuine authenticated remote acceptance. All required GitHub checks, CodeQL, signed packaging/provenance, platform review and postmerge evidence must be green at the exact commit. **Production remains NO-GO** while independent #124/#139/#148 requirements remain unresolved.

## Delivery breakdown

- **S1 — contract and inventory:** this design and source anchors, plus the present draft's narrowly scoped Windows read-only control-plane HTTP cause classifier and its regression fixtures. This is not a cross-platform administration service or completed production acceptance. Follow-on work must extract a reviewed shared health contract for Linux and implement independently authenticated local authority. No live host changes.
- **S2 — rotation backend:** protected local secret adapter with typed mutations, safety boundary and TDD.
- **S3 — lifecycle authorization:** OS-backed, fenced start/stop/restart and durable desired-state tests; no bypass of #96/#80.
- **S4 — operator presentation:** Windows/Linux installer-integrated UI and equivalent headless CLI; UX and security E2E.
- **S5 — production acceptance:** external identity verification, recovery across restart/network loss, signed installers, portable provenance and exact-SHA release review.

This document is **not** an implemented management interface, a completed #248 acceptance checkbox, or authorization to modify the deployed Windows or Linux installations.
