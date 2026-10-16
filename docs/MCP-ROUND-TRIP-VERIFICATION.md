# Verifying a fresh MCP route observation

`verifyMcpRoundTripResponse` and `verifyMcpRoundTripPair` are pure, read-only
caller-side validators for the existing `tunnel_probe` tool. They do not
connect to the tunnel, create a watchdog, read credentials, register tasks,
issue recovery leases, or start/terminate a process.

The **actual MCP client** must authenticate its transport using the platform's
existing connection mechanism, generate a new unpredictable 128-bit lower-case
hex challenge for each request, record trusted local request start/response
arrival times, and impose a separate enforced deadline. It must also supply
the expected Git source SHA and package version from a trusted deployment
record, **not from the response being checked**.

The validator requires the exact challenge echo in both the structured
response and its text representation; a canonical process-scoped UUIDv4; a
canonical UTC timestamp within a bounded 120-second server-clock tolerance;
a local round trip within 30 seconds; and strict, clean Git build provenance
matching the expected SHA/version. The pair validator additionally rejects
reused challenges and changes of server instance between calls.

Only `kind: 'verified'` represents a correctly correlated observation.
Every other outcome returns `kind: 'hold'` with a bounded reason code,
without copying untrusted response text into a log or error message.
An invalid request, malformed response, unknown build identity, expiry,
unexpected revision, wrong challenge, or instance change is **never
permission to restart** or evidence of a particular failure cause.

## Acceptance boundary

The existing portable Windows/Linux CI test invokes `tunnel_probe` twice
over the official MCP SDK and now also runs this strict pair validator
**against the extracted candidate's compiled implementation**. This proves
functional stdio behavior and the verifier contract in an isolated candidate.
It does not probe the installed ChatGPT tunnel, demonstrate external
reachability after a network interruption, or authenticate a process owner
without the platform's transport.

In particular, a timed-out, absent, or malformed response cannot distinguish
MCP child saturation from WAN loss, an unreachable control plane, provider
outage or an intentionally stopped process. Existing recovery fencing remains
read-only and independently requires operator intent, exclusive lease,
process/task identity and fresh source-authenticated evidence before any
later governed lifecycle action. This validator supplies **observation only**.

The nonce is not a secret token, digital signature or cross-process idempotency
key. It proves response correlation only under the calling transport's trust
assumptions. Caller time and expected build SHA must not be populated from
untrusted MCP content. Do not classify this result as a production deployment,
release, signed attestation or autonomous recovery controller.
