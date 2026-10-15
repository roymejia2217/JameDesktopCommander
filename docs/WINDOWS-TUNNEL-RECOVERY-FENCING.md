# Tunnel Recovery Fencing — Pure Preflight Contract

**Status: non-operational.** This module makes no service, task, network,
filesystem or lease changes. It does not issue an authority token or permit.

## Ordering and invariants

The pure `evaluateRecoveryFencing` function recomputes the recovery policy
from an independently supplied durable state and process/network observations.
It returns only `eligible` or a fail-closed `hold` reason.

Eligibility requires, at the time of a trusted observation:

1. The requested durable revision matches the latest state revision.
2. The controller holds the same authoritative lease owner ID and epoch.
3. The lease is still held and has not reached its expiration.
4. The observed task identity has a verified matching SHA-256 fingerprint.
5. The desired state is `running`, the process is absent, networking is
   online, and the recovery policy accepts the attempt budget and backoff.

An explicit `stopped` intent always blocks eligibility. An expired/released
lease, changed epoch, changed executable fingerprint, revised state or
unavailable observation also blocks eligibility.

## Limits, threat model and required future work

**Passing an object with `status: held` or `identityVerified: true` does
not authenticate that statement.** Callers must verify operating-system
identity, file ACLs/DACLs, a monotonic lease generation, trusted clock,
process ownership and task registration using independently trustworthy
Windows facilities. A same-process in-memory lease is not sufficient.

The preflight has a time-of-check/time-of-use gap. A future executor must
hold an exclusive, fenced lease spanning the final state re-read, compare
and task action; it must invalidate stale controllers and serialize
intentional stops. Without that atomicity and authorization, `eligible`
is informational and **MUST NEVER** cause a real start.

No scheduled trigger, retry daemon, Service Control Manager service,
`schTasks` invocation, provisioning or migration is implemented here.
The production runtime must remain unchanged until separate security
and failure-injection reviews approve an operational adapter.
