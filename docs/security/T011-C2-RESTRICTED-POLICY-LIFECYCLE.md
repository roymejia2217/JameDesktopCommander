# T011-C2 — Restricted capability lifecycle (experimental)

**Status:** DRAFT test-support slice. No production MCP handler imports this module.
**Baseline:** `d03fb678d70c1c9e3f2ad1779e237b83f5bc9e10` (accepted T011-C1).

## Tested boundary

`test/security/support/restricted-capability-policy.cjs` is a small, private
prototype wrapping the T011-B/C1 native `RootCapability`. It accepts a trusted
`readVerifiedPolicy()` provider returning `{mode: 'restricted', revision,
allowedRoots}` and a Node-API `RootCapability` class. It does **not** obtain
config from raw user input, and it never exports a handle to the caller.

The manager rejects absent/incompatible native bindings, an unloaded policy,
invalid/empty/unrestricted snapshots, relative/foreign paths, null bytes,
failed disk/config reads, root-open failure, or changed revision/root arrays.
Every byte operation rechecks the verified snapshot. Root selection is only a
lexical *candidate lookup*; the native directory-relative operation provides
the actual filesystem confinement and must continue rejecting symlink and
junction escapes. More-specific configured roots take precedence. Invalid
write argument types and modes are rejected before native mutation.

`reload()` revokes **all** old handles before requesting a new policy snapshot;
it does not silently reuse an outdated root when reload fails. `invalidate()`
revokes and requires explicit reload. `close()` permanently denies access.
An in-flight asynchronous snapshot read carries a generation token: if a
revocation/reload happens during the await, the older result cannot resurrect
handles. Partial multi-root construction closes successfully created handles;
native close failure permanently disables the manager rather than recovering
with stale authority. Errors from the policy boundary avoid disclosing paths.

## Mandatory evidence and limitations

Thirteen mock-based state-machine tests cover stale snapshots, a changed root
with the same revision, read failures, partial native open, concurrent reload,
invalid arguments, absolute/out-of-root rejection, volume-root rejection and
permanent closure. Four additional tests exercise actual Windows and Linux
native Rust addons with disposable inside/outside fixtures: in-root binary I/O,
junction/symlink escape, revocation/reload and denial of ambiguous unrestricted
snapshots. Run both suites under Node 22.19 and 24 in the dedicated native OS
matrix.

**NOT YET production-safe:** `readVerifiedPolicy()` is an injected test-only
contract, not a versioned transaction supplied by `configManager`.
`getAllowedDirectoriesForFilesystem()` currently returns a list (or undefined)
without a stable policy revision and preserves historically unrestricted
`allowedDirectories: []` behavior. This prototype intentionally rejects such
ambiguous/empty inputs; **do not wire it into production as a silent
compatibility break or describe unrestricted mode as a sandbox**.

This synchronous Rust addon still blocks the event loop. Checking the source
revision before a native operation does not by itself give atomic revocation
against external config or filesystem changes. The trusted directory open
must also be defended against policy-root pathname swaps. Native addon
load/packaging/ABI verification and complete handler coverage remain pending.
The type-specific handlers, directory/UI views, PDF edits, search and process
execution remain outside this experimental manager. T011-C3+/D/E must close
those gaps and verify deterministic TOCTOU concurrency on both native OSes.
No installed runtime, service, tunnel, official release or npm publish is
modified or authorized by this incremental test slice.
