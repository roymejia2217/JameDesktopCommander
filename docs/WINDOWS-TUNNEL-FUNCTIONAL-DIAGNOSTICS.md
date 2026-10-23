# Tunnel-client functional diagnostics (read-only)

The `desktop-commander tunnel diagnose` command reads the **official local
tunnel-client admin API** under a hard five-second request limit and a
256-KiB response cap. It accepts HTTP loopback only, rejects redirects
and never prints the health URL, profile paths, tokens, tool names,
process arguments or raw server responses.

The output intentionally says `kind: observational_only`. The dispatcher
error/timeout counters are **cumulative**, not necessarily current failures.
The MCP `tools_list` field reflects the **last observed** discovery and
does not execute a new `tools/list` request. Neither `ready` nor an
observed tools list proves that a fresh `tools/call` will succeed.

This feature makes the known disagreement between generic readiness and
MCP/dispatcher state visible without creating false restart decisions.
It provides **no service supervisor, permission, watchdog or auto-restart**.

Future operational recovery needs an independently verified desired state,
OS-backed fencing through the actual lifecycle action, fresh functional
probe and an isolated Windows loss-and-recovery acceptance test before
production deployment. Tracked under issue #98. Security gate #80
remains deny-only/non-release.

No live tunnel restart or configuration mutation is part of this increment.


## Task Scheduler history when the tunnel is offline

The read-only `desktop-commander tunnel events` command reads the native Windows
Task Scheduler Operational log without contacting the tunnel-client health API,
starting, stopping, or re-registering a task. It is intended for incidents such as
a stopped task with `LastTaskResult=1` and routed MCP `Session terminated`.

The query is bounded to the preceding 72 hours and at most 5,000 Scheduler
records; it emits at most the 50 most recent **matching task** records. Its
`capped` field is true when either bound is reached. An empty or truncated
result is **not** evidence that no other relevant events occurred.

Only UTC timestamps, allowlisted numeric Event IDs (100, 102, 110, 111, 118,
129, 200, 201, 325) and an optional decimal result code for Event 201 appear
in the output. No native event messages, task arguments, profile paths,
process identifiers or raw Windows logs are exported. The native PowerShell
invocation is launched without shell expansion, a 10-second timeout and a
64-KiB output ceiling. The parser rejects unexpected fields and malformed
records; disabled or inaccessible logs fail rather than return a fabricated
healthy status.

Event 201 represents action completion, not the precise cause of a failing
executable. Boot-triggered action starts during an OS reboot must not be
counted as application self-recovery. This diagnostic supplies **no automatic
restart authority or functional MCP round-trip verification**; those
require independent Windows acceptance under issues #96 and #98.
