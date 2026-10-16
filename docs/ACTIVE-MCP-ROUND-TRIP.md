# Active MCP round-trip observation

The `tunnel_probe` MCP tool is a **read-only, nonce-correlated MCP
`tools/call`** operation. It does not open an HTTP endpoint, access a
private tunnel credential, inspect user files or restart a process.

The invoking MCP client generates an unpredictable 16-byte challenge encoded
as **32 lower-case hexadecimal characters** and submits it as
`{"challenge":"<hex>"}`. An accepted call returns:
- `kind: "mcp_tool_round_trip_only"` and `schemaVersion: 1`
- the exact challenge, so the caller can distinguish a fresh response
  from a stale or misrouted one
- a random process-scoped runtime instance identifier
- a UTC observation timestamp
- the previously validated read-only runtime build identity, which may
  explicitly be `unavailable`

### What this proves

If the operator calls this tool through the **actual ChatGPT-connected MCP
route** and validates challenge equality and a bounded client-side timeout,
a correct response proves that **one new MCP tools/call round trip** reached
a responsive server instance over that route at that time. When the tool
is visible through the current remote tool catalog, it also provides
discovery evidence for that client session.

CI also executes two challenge calls via the **official MCP SDK** against
the separately extracted Windows/Linux portable candidate. These tests
prove the packaged protocol behavior; they **do not** exercise ChatGPT's
remote tunnel until that build is safely deployed.

### What it does NOT prove

- It does not authenticate a caller or override the platform's existing
  MCP connection authorization; the random nonce is **not a bearer token**.
- It is not a cryptographic attestation or certificate of build integrity.
- A successful call is not a guarantee of future `tools/list`, other
  tool execution, reconnection, or control-plane availability.
- A failed or timed-out call does not distinguish between network outage,
  tunnel failure, child saturation, provider throttling or caller failure.
- This observation **must never, by itself, authorize any restart**, kill,
  recovery lease, task re-registration or update.
- The currently installed Windows tunnel's older JDC child does not yet
  expose this tool; remote acceptance requires a governed versioned cutover
  and successful rollback exercise.

Use caller-enforced deadlines and per-request unpredictable challenges.
Do not reuse the observation as a long-term health status or rely only on
historical `/health?details=true` counters to decide whether to restart.
