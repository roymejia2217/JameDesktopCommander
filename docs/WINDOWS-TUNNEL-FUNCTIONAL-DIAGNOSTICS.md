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
