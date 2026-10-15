# Windows Tunnel Recovery Policy — Decision Contract

**Status: design-stage, non-operational.** This is not a background monitor,
Windows service, deployment, availability guarantee, or permission to restart
the installed OpenAI Secure MCP Tunnel.

## Ownership and safety boundary

The pure `decideTunnelRecovery` function classifies a supplied snapshot
without executing any task or touching disk, network, credentials, or processes.
Its `start_candidate` result is **not an authorization**.

A future Windows lifecycle controller must independently guarantee:

1. Authenticated, durable desired state, including a persistent intentional stop.
2. An exclusive recovery lease preventing concurrent controllers and duplicate starts.
3. Verified Scheduled Task registration, executable identity and process ownership.
4. Persistent attempt history, budget, bounded exponential backoff and clock handling.
5. An authoritative health probe, not merely a Running task or open TCP port.
6. A controlled lifecycle operation and independent post-start readiness acceptance.
7. Non-sensitive structured events and service-manager-compatible diagnostics.
8. Installation-independent contract tests plus real-host failure/recovery tests.

Without these prerequisites, a start candidate must **not** be executed.

## Decision semantics

- `stopped` or `unknown` desired state never starts a tunnel.
- A running tunnel with degraded health requires investigation; it is not killed
  automatically by this policy.
- Missing or contradictory observations yield a hold or operator intervention.
- The network must be explicitly online before an absent tunnel qualifies.
- The bounded retry budget is authoritative and does not reset implicitly.
- Inconsistent retry history or clock regression never authorizes a start.
- Retry delay doubles per previous attempt and is capped by `maxDelayMs`.
- The policy intentionally has no periodic scheduling, retry loop or side effects.

An error from malformed inputs is a fail-closed result at the caller boundary:
it is never safe to interpret an exception as `start_candidate`.

## Scope and evidence

This increment defines the **eligibility contract only**. It neither stores
desired state nor wires a controller into Task Scheduler or Service Control
Manager. Automated recovery remains disabled pending independent implementation,
review, security checks and safe isolated end-to-end validation.

The 2026-10-15 incident showed that the existing boot-only tunnel and remote
tasks can be stopped while Windows and networking remain available. It also
showed that an on-demand restart supervisor is not an always-on watcher.
Operational host paths, private configuration, credentials and local logs
must remain outside the public repository.
