# T011-C4c — Protected authority operation data contract

**Status:** Experimental contract and regression coverage; **no broker,
trusted authorization, IPC, or production filesystem migration**.
Build baseline: protected `main` `ec3577dc20b56d87557fecbad241eea196d64010`.
This increment must remain unpublished and is not release-eligible.

## Security boundary and responsibility

The MCP Node process, its local JSON config, and all model-originated paths
are **untrusted inputs**, not the filesystem authority. A future authority
must run under an independently protected OS identity, hold separately
protected durable policy state, authenticate its IPC peers, and perform
the entire filesystem operation itself using pinned native directory handles.
A user process running as the same unrestricted principal does not provide
that separation. A checksum, file watcher, or stored client-side epoch is
not an authority; unmanaged policy A -> B -> A remains an attack.

`src/security/authority-operation-contract.ts` validates only **data**.
No public MCP tool imports it. The existing AST isolation gate now rejects
attempted imports from production `src` modules. This is a source-level
accidental-wiring guard, not protection from malicious local code.
## Protocol shape (version 1, object-level validation only)

- `create-directory` request: `version: 1`, `kind`, UUIDv4 `requestId`,
  canonical base-10 uint64 `expectedEpoch` (1..2^64-1), 32-character
  lowercase hexadecimal `rootRef`, slash-delimited `relativePath`.
- `rootRef` identifies a broker-owned, pinned root only; it is **not a
  bearer token**, a proof of authorization or a pathname to reopen.
  The authority must bind it to authenticated caller, policy epoch and OS
  directory identity at the operation boundary.
- Relative paths are bounded (4096 UTF-8 bytes, up to 64 components, each
  at most 255 bytes) and reject traversal, absolute/UNC/drive paths,
  backslash, Windows ADS and reserved devices, control characters and
  trailing dot/space ambiguity. Only native handle confinement can prove
  OS-level safety, including junctions, symlinks and hardlinks.
- Object messages are capped at 8192 UTF-8 bytes, require exact fields,
  primitive data and canonical identifiers, and reject extra/accessor/
  inherited data without running nested serialization callbacks.
- Result: matching `requestId`, `kind: operation-result`, `version: 1`,
  and either `status: committed` with canonical `committedEpoch`, or
  `status: rejected` with a closed set of machine-readable error codes.
  A completed result describes **already completed broker-side I/O**.
  It must never be interpreted as permission for Node to access a path.
- `requestId` is a correlation identifier, **not replay protection**.
  `expectedEpoch` is an advisory concurrency precondition, **not a
  client-verifiable monotonic authority**. Both require broker enforcement.
## Authority implementation gates still required

1. Independently provision and protect a Windows service identity/state
   and Linux equivalent, with authenticated peer credentials, precise ACLs,
   administrator-only policy control and real cross-principal denial tests.
2. Define and verify IPC framing/encoding and message authentication by OS
   identity. Reject duplicate JSON fields, noncanonical encodings, unknown
   versions and oversized frames **before** object validation. This module
   does **not** implement byte framing, JSON parsing or IPC.
3. Persist a monotonic policy epoch outside the config editor's trust domain.
   Prove A->B->A replay and rollback resistance, crash/restart and invalid/
   missing store handling; failure to reach the broker must deny requests.
4. Serialize authorization, revocation and the native operation under the
   same trusted epoch. Deny stale and uncommitted work; specify in-flight
   commit ordering and rejection after revoke. Never return an ambient path
   approval to Node for reopening.
5. Use nonblocking bounded native I/O, cancellation, shutdown and recovery;
   test Windows/Linux namespace swaps, link and volume attacks, resource
   caps, concurrent updates and loss of broker connectivity.
6. Review deployment and supply chain independently before any change to
   portable packaging, installed services or the public MCP catalog.

## Evidence and explicit limitations

`test/test-t011-authority-operation-contract.js` exercises canonical
requests, invalid revisions/identities, unsafe paths, alternate return
shapes and JSON serialization side effects. The regression was observed
RED then fixed GREEN. `test/test-t011-authority-isolation.js` also
demonstrates RED->GREEN for attempted source import of this contract.
These tests do **not** prove an authenticated broker, monotonic storage,
revocation correctness, native confinement, or production TOCTOU repair.
T011-C4b trusted authority and T011-C5+ handler migration remain OPEN.
