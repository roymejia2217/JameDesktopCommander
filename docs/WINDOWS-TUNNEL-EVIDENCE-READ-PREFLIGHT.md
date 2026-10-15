# Tunnel recovery: read-only evidence adapter

**Status: non-operational.** This does not provide a trusted Windows source,
acquire a lease, authenticate a controller, or start, stop or monitor a service.

The `RecoveryEvidenceReader` interface separates reads of persisted intent,
the authoritative OS lease, task identity, observed process/network health, and
time. `probeRecoveryEvidenceReadOnly` collects two complete sequential sets.
Inconsistent observations, clock regression, unavailable data and invalid
schemas fail closed. The final observation is evaluated against the existing
recovery/fencing contract.

A positive result is named `candidate_only`, deliberately **not permission**
to perform a Windows lifecycle action. The provider must independently verify
native principal and token, ACL/DACL ownership, task/executable identity,
lease generation and process ownership before any real authority is possible.

The two-pass design detects observable drift but **cannot eliminate TOCTOU**:
an operator can STOP immediately after the second read. A future executor
must hold a truly exclusive and OS-enforced lease through the final state
read and the action. Synthetic providers can lie; no in-memory booleans,
claims or UUID fields are considered proof of authority.

The full real-host security gate remains issue #80 (SCM deny-only, non-release).
Recovery rollout remains gated separately by issue #96. No installed runtime,
host configuration, secrets, process or task is modified in this slice.
