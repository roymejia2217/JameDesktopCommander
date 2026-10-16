# Remote Device terminal-result acknowledgment contract

`RemoteChannel.updateCallResult` must not equate an HTTP-success response
with a committed terminal result. A PostgREST `UPDATE` without `.select()`
can return success without proving that any row was updated. A late response
may otherwise overwrite an already completed, failed or timed-out call.

## Confirmed publication

A terminal write is conditional on the row still being `executing`,
with `timeout_at` strictly later than the current time, and
uses PostgREST `.select('id')`. It is **confirmed** only when there is no
PostgREST error and exactly one returned row has the requested identifier.
No rows, multiple rows, the wrong identifier, errors or missing data are
**unconfirmed**. The code does not print identifiers, arguments or results.

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
wrong identifiers, concurrent terminal writes, deterministic rejection,
lost acknowledgments and sanitized failure publication. They do **not**
exercise the live Supabase database, its actual RLS policies, SQL triggers,
cross-process isolation or the ChatGPT route. Hosted CI and a disposable
Supabase integration acceptance are independent gates.

The pre-existing `markCallExecuting` still returns a permissive result on
some database errors. An in-memory `seenCallIds` guard prevents duplicate
delivery only within one running device process; it cannot establish
exactly-once behavior across processes or restarts. Changing claim behavior
requires a separate fail-closed transactional acceptance slice and review
of doorbell's preclaim path. Do not claim exactly-once distributed execution
on the basis of terminal publication tests.

This slice changes neither task registration nor service installation,
and does not restart the production Windows tunnel.
