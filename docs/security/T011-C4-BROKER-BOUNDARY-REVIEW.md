# T011-C4 - Out-of-process filesystem broker: security design gate

**Status:** PROPOSED FOR INDEPENDENT REVIEW; NOT ACCEPTED OR IMPLEMENTED.
**Base:** protected `main` at `a2c660aab9b3268ae525ccd1ccb4b2798318de47` (2026-11-13).
**Scope:** #139, subject to independent #148 and #124 gates. No runtime/service/release grant.
**Canonical inventories:** [filesystem handlers](T011-C-HANDLER-CALLGRAPH-DECISION.md),
[object isolation](T011-HARDLINK-OBJECT-ISOLATION-DECISION.md),
[filesystem boundary](T011-FILESYSTEM-CAPABILITY-BOUNDARY.md).

## 1. Evidence versus implementation

- PRs #318 and #319 are merged. The latter proved a real Linux `nobody`
  UID/GID/PID peer observed through `SO_PEERCRED` on a test-owned socket.
  The test runner, not a provisioned `jdc-authority` process, served that socket.
- `native/authority-service/src/main.rs` still exits with `E_POLICY_UNAVAILABLE`.
  `native/authority-store` documents that pathname-open SQLite transactions
  do not establish protected state custody or full-store rollback prevention.
- Existing MCP file handlers still authorize a pathname before separate
  Node/adapter path I/O. The canonical callgraph lists the actual routes.
- Historical draft #207 proved an isolated Linux issuer read through actual
  system principals and a hosted fixture, but was CLOSED UNMERGED as a
  superseded research stack. Its historical PASS does not apply to this main
  tree, establish anti-rollback, or permit cherry-picking the stack unseen.
- #148's real Windows/Linux hard-link tests disproved outside-object isolation
  in the old capability research. #124's historical N-API lifetime model is
  not approved. Neither issue is resolved by the Linux peer test.

## 2. Decision under review: one independently authenticated broker

The only eligible implementation direction is a separately provisioned,
least-privilege OS process retaining its own policy, anchored root handles,
open file handles, and per-request authorization state. The Node MCP process
must receive only bounded bytes or categorical errors. It must never receive
raw descriptors, unrestricted root handles, a pathname grant, or a reusable
capability token. No file operation may fall back to `validatePath()+fs.*`.

The broker must reject startup when its installed identity, authorized client
principal, protected policy source, revision anti-rollback anchor, or root
custody cannot be proved. Neither a local username nor a self-reported PID,
`rootRef`, environment variable, pipe/socket pathname or CLI flag grants
privilege. A failed bootstrap is not permission to run in the user's context.

**Unresolved legitimate-client bootstrap:** today the portable MCP process
runs with the interactive user's ambient identity, not automatically as a
separately provisioned `jdc-mcp-client`. The installation/launch chain must
prove how a genuine client obtains its protected origin and how another
process under the **same** UID/SID is excluded from reusing it. Matching
Unix UID/GID or a Windows user SID, inspecting a client PID/image name, or
passing a nonce through user-readable configuration is insufficient alone.
No automatic identity switch, privileged wrapper or grant is approved here.

The research-only native N-API object remains excluded. Out-of-process IPC
avoids invoking its unproven ownership mechanism but does **not** close #124.
No production listener, file operation, or installed service is enabled by
this proposal.

## 3. Proposed one-read protocol and operation lifetime

This is an **interface review sketch**, not an executable protocol or an
approval of the values below. No implementation may accept these fields as
authority before an independent design disposition.

| Property | Mandatory behavior |
| --- | --- |
| Envelope | Versioned, canonical, length-bounded framing. Unknown version, malformed, duplicate, partial or trailing frames DENY. |
| Scope | Initial eligible operation is `READ_REGULAR` only; no write, append, create, delete, list, search or metadata delegation. |
| Client identity | Verified from the OS on the accepted IPC connection and bound to the connection lifetime. Caller-provided UID/SID/PID is ignored. |
| Root selection | An opaque ID may *reference* an admin-provisioned root, but cannot create, replace or widen a root. Relative child components only. |
| Policy | The broker owns a protected immutable request snapshot, policy epoch and a proven restart-safe anti-rollback source. Client epoch is a stale-request check, never authority. |
| Replay | Unique operation identity plus an atomic server-side consumed/claimed state; replay, crash ambiguity and store disagreement deny. |
| File custody | Resolve relative to the retained root; open and read only an OS-authorized object with validated storage provenance. No pathname reopen. |
| Response | Bounded byte payload after authorization; otherwise one of `DENIED`, `UNAVAILABLE`, `UNSUPPORTED`, `NOT_FOUND` without sensitive path disclosure. |
| Cancellation | Bounded time/bytes and explicit handle cleanup; cancellation cannot leave a detached authorized task. |

Authentication is not authorization. Linux `SO_PEERCRED` reports credentials
at connection time; it does not prove future custody after descriptor transfer.
A real adversarial test must establish that a transferred/reused connection
cannot gain another principal's authority. Reject ancillary descriptor transfer
or other delegation unless a separately reviewed design can prove it safe.

A policy revocation may be acknowledged only after every old-epoch read
has stopped issuing I/O and sending response bytes, with outstanding streams
closed or finished. Already-transmitted bytes cannot be retracted, even if
still buffered in the OS or retained by a client; a broker-side acknowledgement
is **not** proof of their absence at the receiver. Any stronger no-delivery
claim needs a separately verified client-drain/receipt protocol. Timeout,
crash or uncertain transport state must deny a positive acknowledgement.
New reads require the new epoch. Review and test these linearization points
before activation; never infer revocation safety from a cancelled promise.

## 4. Platform and object-isolation dependencies

**Linux:** the initial disposable proof must run the *server* as the real
independently provisioned `jdc-authority` UID/GID and the client as a distinct
approved `jdc-mcp-client` identity. Verify group custody, parent/socket
ownership/modes, root storage provenance, actual kernel peer credentials,
systemd FD custody if inherited, and no unapproved descriptor delegation.
A root-relative `openat2` resolution proof can establish pathname confinement,
not the stronger hard-link invariant by itself.

**Windows:** an equivalent separately authenticated service/SID and named
pipe require an explicit DACL, exclusive local endpoint, token and process
lifetime checks, and checked `ImpersonateNamedPipeClient` / `RevertToSelf`
semantics. A failed impersonation must abort before touching the filesystem.
No Windows production counterpart is currently approved.

**Both:** #148's invariant O forbids reading outside-object bytes through
an in-root hard-link alias as well as changing them. A link-count test, a
path-prefix check and a confined open alone are insufficient. An approved
storage-domain and principal boundary must eliminate unauthorized object
aliasing under the explicit threat model, including preexisting aliases and
concurrent modifications. If the host cannot meet that contract, restricted
read must return `UNSUPPORTED` before disclosing bytes.

Explicit `allowedDirectories: []` retains its existing **unrestricted** legacy
meaning; do not relabel it isolated. A configured restricted policy with a
missing native backend must fail closed, but an all-deny prototype is not a
substitute for proven legitimate in-root reads. Process execution, OpenCode,
URL fetches and delegated search remain separate ambient-authority surfaces.

## 5. Acceptance sequence and review decision record

1. Independent security reviewers must decide supported storage/volume/mount
   models, service/client principals, IPC custody, anti-rollback mechanism and
   the exact object-origin invariant; record concrete approval or rejection.
2. Preserve the original hard-link and namespace-swap RED evidence. On real
   disposable Linux, prove an actual `jdc-authority` server serves one valid
   bounded read, rejects a foreign client, stale/replayed/revoked operations,
   symlink, final-component swap and hard-link alias, and verifies exact
   outside-sentinel bytes. Attack setup must itself be confirmed.
3. Verify restart, cancellation and concurrent revoke versus read. No
   response after acknowledged revocation; no leaked handles or plaintext
   on failed requests. The test must exercise the actual compiled broker.
4. Repeat corresponding proofs on real Windows under an actual service
   identity. Do not infer Windows parity from Linux or from a service-token
   observer that performs no filesystem operation.
5. Only then propose a *separate reviewed* production integration covering
   the canonical handler callgraph and in-memory document processors, with
   official MCP SDK tests on independently extracted Windows/Linux packages.
   Preserve all existing T008-T010 semantics and tool error contracts.
6. Require exact-head mandatory CI, native acceptance, CodeQL, governance,
   installers and independently checked postmerge `main`. Never bypass the
   existing production isolation gate to make research code reachable.

**Open reviewer decisions:** Which operator owns immutable roots? Which
filesystems and external aliases are permitted? What OS-protected monotonic
state survives rollback/reinstall? How is the actual interactive-user MCP
launched as a verified client without granting access to another same-UID/SID
process? How are transferred descriptors excluded? How are previously sent
bytes distinguished from revocation-acknowledged future sends? What evidence
proves Windows named-pipe parity?

**Disposition:** REVIEW REQUIRED / NO IMPLEMENTATION PERMISSION.
The current `main` continues deny-only for the native authority; #124, #139
and #148 remain P0. `releaseEligible:false` and production NO-GO remain.

## Official primitive references

- [Linux Unix-domain peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html)
- [Linux anchored path resolution](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [Windows named-pipe client impersonation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [Windows hard links and junctions](https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions)
