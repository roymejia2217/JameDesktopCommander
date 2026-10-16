# Remote Device: fail-closed execution claims

A command must not run merely because a notification arrived, a local
process previously saw its ID, or a database request was attempted.
A normal claim must have an **acknowledged conditional update** of
exactly one `mcp_remote_calls` row, matching both the call ID and this
device ID, transitioning `pending -> executing` before expiry.

## Durable ownership versus local deduplication

`markCallExecuting` now refuses missing identity, network and database errors,
lost acknowledgments, empty responses, multiple rows, and responses for
another device or call. It does **not** re-claim an ambiguous update or infer
ownership by reading back an `executing` row: another process could hold it.
This trades some failed calls/timeouts for prevention of duplicate
side-effecting executions. Normal retries are safe only while the row
remains `pending`, and are handled by the existing durable recovery scan.

The Broadcast/Presence doorbell path already performs a pending-to-executing
conditional update and dispatches the accepted row locally. A
process-internal `WeakSet` tracks **only the exact event object**
dispatched by that channel after this claim; a public `claimed: true` field,
cloned event, or arbitrary callback argument must not bypass the database.
The process-local bounded seen-ID cache remains a supplementary defense,
not a distributed lock.

## Adversarial acceptance and limits

The tests cover wrong/extra returned rows, mismatched device/ID, null
responses, thrown transport errors, ambiguous acknowledgments, forged
`claimed` fields, verified internal deliveries, and two independent
`MCPDevice` instances competing for one atomic fake database row. They
also exercise existing transport and terminal-result publication tests.

This is **not** a test against live Supabase, its RLS policies or PostgreSQL
transactions. Production exactly-once side effects are not guaranteed:
a process could execute an external tool, crash before publishing, and
leave an indeterminate result. Real durable exactly-once would require
idempotency at the tool boundary or a stronger server-managed lease/
execution journal, and a separate governance review.

No watchdog, task restart, privileged SCM operation, production database
mutation or installed tunnel update belongs to this slice.
