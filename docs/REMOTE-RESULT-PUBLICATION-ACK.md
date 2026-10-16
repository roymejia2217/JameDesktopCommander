# Remote Device terminal-result acknowledgment contract

`RemoteChannel.updateCallResult` must not equate an HTTP-success response
with a committed terminal result. A PostgREST `UPDATE` without `.select()`
can return success without proving that any row was updated. A late response
may otherwise overwrite an already completed, failed or timed-out call.

## Confirmed publication

A terminal write is conditional on the row still being `executing`,
with `timeout_at` strictly later than the current time, and
uses PostgREST `.select('id,status')`. It is **confirmed** only when there is
no PostgREST error and exactly one returned row matches the requested
identifier **and** the requested terminal status (`completed` or `failed`).
No rows, multiple rows, an unexpected terminal status, the wrong identifier,
errors or missing data are **unconfirmed**. The code does not print
identifiers, arguments or results.

The existing caller emits `result_published` only after an explicitly
confirmed `completed` update. If PostgreSQL **definitively rejected** a
result because of invalid encoded text bytes (SQLSTATE `22P05`), the channel
may write a sanitized, fixed-message terminal `failed` status instead. Only
its separately confirmed acknowledgment allows `failure_published`.

If a network failure or missing acknowledgment follows an attempted write,
the database might actually have committed. The channel must **not retry
with a different terminal status**. The device emits
`result_publish_failed` (an evidence/acknowledgment failure), without
claiming execution failed and without overwriting a potentially successful
call. Recovery or operator escalation requires an independently authorized
fresh state read. No automatic process restart is authorized.

## Scope and unproven conditions

These tests use real application methods and an in-memory modeled
PostgREST update boundary. They cover zero-row updates, duplicate results,
wrong identifiers and terminal statuses, concurrent terminal writes,
deterministic rejection, lost acknowledgments and sanitized failure publication.

A separate isolated integration contract additionally starts an actual MCP
server child through the official MCP SDK client and calls the real Remote
Device claim, execution and publication paths against a state-bearing
PostgREST model. It verifies confirmed completion, contradictory ACKs after a
modeled commit, and mid-call child termination. Only the MCP stdio execution
uses an actual process and protocol; the database remains simulated.
Neither test tier exercises a live Supabase database, its RLS policies,
SQL triggers, cross-process isolation or the ChatGPT route. Hosted CI and a disposable
Supabase integration acceptance are independent gates.

The existing `markCallExecuting` rejects missing, contradictory and
indeterminate claim acknowledgements. A process-local `seenCallIds` guard
prevents duplicate delivery only within one running device process; the
conditional database claim is the separate distributed ownership boundary.
The local PostgREST model does not prove real RLS policies, atomicity across
physical processes or exactly-once execution across recovery and retries.
These require independent disposable-database and provider acceptance.

This slice changes neither task registration nor service installation,
and does not restart the production Windows tunnel.
