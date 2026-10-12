# T011-C4d — Canonical bounded authority frames

**Status:** Experimental DATA framing only, not an authorized IPC channel,
a privileged broker or an installed service. Baseline protected `main`:
`49b6480137ce98bd13fd7cbd407604bde64d1b02`.
The production filesystem handlers and deployed runtime remain unchanged.

## Wire format and canonicality

Exactly one complete frame comprises a 4-byte unsigned big-endian payload
length followed by 2–8192 bytes of UTF-8 JSON. There are no trailers,
bundles, partial-frame acceptance or unbounded accumulators. The framing
functions accept only Node `Buffer`, perform an isolated snapshot, reject
oversized input before allocation, check length equality and decode using
fatal UTF-8 validation.

The payload is one compact JSON object with no whitespace and a fixed
per-message field order. `JSON.parse` must succeed, C4c's strict
operation-data validator must succeed, and canonical reserialization must
match the original bytes exactly. Consequently duplicate JSON members,
unknown members, escaped aliases, divergent property order, leading BOMs,
lossy UTF-8, numbers with alternative spelling and appended payload bytes
are not accepted. Strings with unpaired surrogate code units are rejected
before canonical emission and after decoding.
## Operations carried in version 1

- `create-directory` request fields, in exact order:
  `version,kind,requestId,expectedEpoch,rootRef,relativePath`.
- `operation-result` committed response fields:
  `version,kind,requestId,status,committedEpoch`.
- `operation-result` rejected response fields:
  `version,kind,requestId,status,errorCode`.
- All messages must satisfy the C4c contract, including uint64 epoch
  strings, opaque 32-hex root references, UUIDv4 correlation, safe relative
  path checks and closed rejection-code vocabulary.
- `requestId` is correlation, **not an anti-replay capability**. A root
  reference is a selector, not a bearer token. `committed` is notification
  of a completed broker-side native operation, never a pathname grant.

## Unimplemented protected boundary

Framing is not streaming transport, IPC authentication, request replay
tracking, trusted monotonic policy storage, native filesystem execution,
credential provisioning, or concurrency/revocation ordering.
A privileged, independently administered authority must authenticate the
OS peer identity, enforce permissions, select pinned native directory
handles and serialize policy epoch transitions with native I/O. The
authority must also bound receive buffering and timeouts **before**
calling these complete-frame helpers; disconnects must deny operation.
Running both processes with the same unrestricted user does not meet the
separation requirement.
## Test and release gates

- `test/test-t011-authority-frame-contract.js` tests deterministic
  bytes, round trips, complete-frame length checks, double frames, malformed
  UTF-8, BOM, noncanonical/duplicate JSON, forged result correlation,
  Unicode scalar values and callbacks that must never execute.
- Existing C4c tests remain unchanged and the C4b AST isolation gate
  explicitly forbids importing the new module from productive `src`
  handlers. Only the definition-only C4d module may import C4c's shape.
  This exception does **not** grant authorization.
- Node 22.19 and 24, Windows and Linux, required CI and protected-main
  postmerge acceptance must pass before this increment is integrated.
- No change to external MCP schemas, native addon ABI, dependency graph,
  packaging release eligibility, tunnel, host service or installed runtime.

**Remaining release blockers:** independently protected OS identity and
state, replay-resistant epoch persistence, authenticated IPC, linearizable
revocation, namespace-safe native operations, nonblocking cancellation,
and migration of the entire affected filesystem call graph including
`createDirectory`. There is no security signoff until those are proven.
