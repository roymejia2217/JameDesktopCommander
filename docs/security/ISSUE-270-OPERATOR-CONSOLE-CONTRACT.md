# JDC local operator console — release-critical interface contract

Status: IN PROGRESS, **NOT a release authorization**. Issue #270 owns the
installed Windows/Linux backend + native Rust/egui frontend; #248 owns
full user acceptance. Security issues #124, #139, #148 remain independent P0s.

## Architecture boundary

- A **single** operations backend owns OS lifecycle, credential transactions,
  desired-state fencing and official tunnel-client verification. No GUI-owned
  service controller, unauthenticated loopback HTTP server or duplicate state machine.
- The native Rust/egui app is a presentation client. It may display **read-only**
  diagnostic evidence without any permission to mutate service state or keys.
- Privileged backend operations later require independent interactive operator
  authorization, validated installed instance identity and exact target custody.
  Same SID/UID as a remotely controlled MCP process is **not authorization**.
- Invoke the packaged backend **without a shell**, with a pinned executable
  identity, fixed arguments, bounded stdout/stderr and a versioned response.
  Do not let a user-configurable path, environment value or profile edit
  select a privileged executable. Never put a key on argv or in the environment.

## Current incremental contract (Windows observer)

Command: `desktop-commander tunnel overview` — no flags, **read-only**.
Versioned object: `tunnel_operator_overview_v1`; schema owner:
`src/platform/tunnel-operator-overview.ts`.
Fields are bounded and enumerable: `platform`, `capabilities`,
`observedAt` (local sample wall clock, not remote delivery proof),
`taskRegistration`, `localHealth`, `mcpInitialize`,
`toolDiscovery`, `controlPlane`, `remoteDelivery` and a typed
`verdict.state` plus `verdict.reasonCode`. No profile path, URL, token,
provider message, raw task XML or account metadata is serialized.

- Registration observed: the registered task was read; **not** proof that
  the executable is running or entitled to rotate credentials.
- Local ready: observed client health; **not** remote MCP availability.
- Control-plane `credential_rejected` / 401: a rejected credential, **not**
  proof of expiration. 403 and 429 must be represented separately.
- The remote round trip remains `not_observed` until an independently
  authenticated remote request/result witness exists. Never show Healthy
  from a readiness endpoint or local tools/list alone.
- Unavailable or contradictory sources produce fixed `unverified` reason
  codes. Do not include exception text; GUI must show remediation actions
  based only on code and verified provenance, not raw provider strings.

## Cross-platform compatibility

The Windows GUI consumes `tunnel_operator_overview_v1` with
`platform: win32`. Linux now exposes an independently versioned, read-only
CLI projection via `desktop-commander tunnel overview`:
`tunnel_operator_linux_overview_v1` with `platform: linux`,
`serviceRegistration` (not the Windows `taskRegistration`),
and the same bounded observational evidence categories. It reuses
the existing Linux `status` and `diagnose` custody/OS readers; if a
read fails or observations conflict, the result stays unverified.
It does not include source paths, profile names, secret references,
raw provider errors, or a claimed remote ChatGPT MCP round trip.

The Windows GUI schema is unchanged. The Rust GUI does **not** yet accept
the Linux contract and the Linux .deb does **not** package an operator GUI.
Linux interactive UX, accessibility, authenticated privileged controls,
live remote acceptance, and full #150/#248 closure remain separate work.
Never claim Linux desktop parity from the CLI observer alone.

## User-test milestones and required ordering

1. **Read-only real UX early:** ship Windows native Rust/egui Overview and
   Diagnose that consume the versioned backend output, show provenance,
   freshness, offline/stale/unknown states, keyboard focus and accessible
   labels. No Rotate, Start or Restart action is authorized by this milestone.
2. **Authorization boundary:** Windows token SID, registered Task Scheduler
   principal and actual file/ancestor custody; Linux UID/systemd-user and
   effective profile/environment provenance. Prove remote same-user MCP
   processes cannot invoke local privileged actions.
3. **Transactional operations backend:** safe Windows file exchange and Linux
   installed transaction binding, bounded one-shot secret input, serial lease,
   durable STOP, cancellation, crash recovery and rollback with real OS tests.
4. **Controlled UX actions:** enable credential rotation and lifecycle only
   when gated backend operations pass. Show transaction progress, failure,
   unknown outcome and manual recovery; never show an unproven success badge.
5. **Installable acceptance:** Windows signed/verifiable .exe and Linux .deb
   bundle their matching backend and UI; headless Linux exposes equivalent
   CLI. Clean machine install/uninstall, offline recovery, provider 401/403/429,
   actual official client authentication and separate remote ChatGPT MCP
   end-to-end acceptance are required before closing #270/#248/#150.

Work at most one independently reviewable PR per operations lane. Evidence
must include RED/GREEN tests, real Windows/Linux host checks as applicable,
exact-SHA CI, protected squash with blank body and new-main postmerge CI.
No polling loop or release from synthetic/screenshot-only evidence.
