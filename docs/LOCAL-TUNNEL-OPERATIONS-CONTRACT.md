# Local tunnel administration and credential recovery — contract proposal

**Status:** design-only; no runtime implementation, authorization grant, service installation, or release approval.  
**Tracking:** #248. Dependencies/related boundaries: #96, #98, #150, #32; security release gates #124, #139, #148.  
**Targets:** Windows installer (`.exe`), Linux installer (`.deb`), with equivalent headless Linux CLI for basic management.

## Problem demonstrated

A real operator incident on 2026-11-03 combined all of the following: the Windows Scheduled Task was running; the official tunnel-client process had an established outbound connection; local `/healthz` and `/readyz` returned 200; the official *component* health disclosed control-plane HTTP 401 and sustained authentication failures; MCP stdio initialize/tools-list had not been observed; remote ChatGPT calls failed with client-facing 404/429. The dedicated runtime API key had expired. Replacing the secret in a local protected file and restarting the installed tunnel task restored fresh ChatGPT MCP operations.

**Invariant:** process/task liveness, TCP connectivity and local readiness must never be displayed as proof that authenticated control-plane polling or fresh MCP tool delivery works. A remote-visible 404/429 is not sufficient to classify the independent HTTP 401. A 401 proves credentials were rejected, **not** why; claim an expiration only with independently authenticated provider metadata or a trusted stored expiry date. A successful `doctor` config check does not validate remote credential acceptance.

The incident details are intentionally sanitized: no usernames, exact host paths, profile IDs, private URLs, key IDs, credentials or process IDs belong in this public design or support exports.

## Verified existing integration surface

| Current component | Existing behavior (protected-main source) | Missing operator guarantee |
| --- | --- | --- |
| `src/npm-scripts/tunnel.ts` | Windows tunnel command dispatch, native task lifecycle, status, diagnose and events | No credential rotation or local management UI |
| `src/platform/windows/tunnel-functional-diagnostics.ts` | Bounded loopback-only read of official admin `/health?details=true`; `observational_only`; cumulative counts, MCP initialization and discovery observations | Does not surface typed control-plane HTTP error cause; no verified fresh MCP request |
| `docs/WINDOWS-TUNNEL-RECOVERY-FENCING.md` | Pure recovery preflight; **non-operational** and not an authority token | No OS-enforced privileged recovery executor |
| `src/platform/linux/tunnel-lifecycle.ts` / `docs/LINUX-TUNNEL-LIFECYCLE.md` | Development-only managed `systemd --user` lifecycle, official-client preflight and status; deliberately stopped state preserved | No shipped local control UI, no credential-rotation path or real authenticated remote E2E |
| `docs/DISTRIBUTION-CANDIDATE.md` | Portable **unpublished** test candidates, `releaseEligible:false` | Not a signed Windows `.exe` / Linux `.deb` local-management distribution |

The installed third-party tunnel-client, existing UI bridge and OpenCode gateway are **separate components**. Installation-specific service paths and secret stores remain outside Git. UI Bridge presence is *not* authorization to control the tunnel or read secrets.

## Proposed public status contract (not implemented)

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

- **S1 — contract and inventory:** this design and source anchors; next PR adds a pure typed status classifier with explicit RED→GREEN regression tests. No authority and no live host changes.
- **S2 — rotation backend:** protected local secret adapter with typed mutations, safety boundary and TDD.
- **S3 — lifecycle authorization:** OS-backed, fenced start/stop/restart and durable desired-state tests; no bypass of #96/#80.
- **S4 — operator presentation:** Windows/Linux installer-integrated UI and equivalent headless CLI; UX and security E2E.
- **S5 — production acceptance:** external identity verification, recovery across restart/network loss, signed installers, portable provenance and exact-SHA release review.

This document is **not** an implemented management interface, a completed #248 acceptance checkbox, or authorization to modify the deployed Windows or Linux installations.
