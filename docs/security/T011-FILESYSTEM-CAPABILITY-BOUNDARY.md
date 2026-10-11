# T011 — Race-resistant filesystem capability boundary

**Status:** Proposed architecture and mandatory release blocker, **not implemented or accepted**.
**Platforms in scope:** Windows x64 and Linux x64; native CI and unpublished portable candidate.
**Baseline:** `4c30d5a36e5f3ba52344f8edee783f1cc7197c55` (T010 accepted after independent postmerge artifact audit).

## Evidence and threat model

JDC currently resolves and authorizes a pathname using `validatePath()`, then
may open/read/write/rename it in a separate filesystem operation. A concurrent
filesystem namespace mutation between these operations can invalidate the
authorization decision. On the independently verified Linux portable bundle,
a controlled adversarial test using disposable directories demonstrated that
an operation returned success while its effect landed outside the configured
`allowedDirectories`. No live user files, installed services, gateways or
tunnels were involved. Exploit setup and timing are intentionally not published
before remediation.

**Adversary assumptions:** another process with permission to mutate a path
component, including symbolic links on Linux or reparse points/junctions on
Windows. Protection must also hold for races involving a final file component.
The application cannot claim OS-level isolation against an account with
broader host permissions or against command execution using ambient authority.

**Non-solutions:** repeatedly calling `realpath()`, adding `lstat()` checks,
comparing path strings after an open by filename, or using `O_NOFOLLOW` only
on a final pathname component. These do not, by themselves, bind all parent
components to a trusted directory handle.

## Proposed architecture (subject to proof)

Evaluate a small **capability-oriented native filesystem adapter** implemented
as a maintained Rust library exposed to Node with a maintained Node-API binding.
The leading investigation candidates are
[Bytecode Alliance cap-std](https://github.com/bytecodealliance/cap-std)
and [napi-rs](https://github.com/napi-rs/napi-rs). Their upstream claims are
inputs for verification, **not acceptance evidence for JDC**.

1. Open each **verified allowed directory** as a trusted, anchored directory
   capability. Expose opaque capabilities to TypeScript; do not expose ambient
   filesystem handles, raw file descriptors or unrestricted file-opening APIs
   to untrusted requests.
2. Resolve each requested child path **relative to an anchored root**, with
   traversal and symlink/junction escape prevented during the native open.
   Lexical prefix checks may select a candidate root, but must never be the
   definitive authorization proof.
3. Make file reads, writes, append, create, move and directory changes operate
   on the bound object or a confined relative child of a capability. No
   unvalidated pathname reopening after authorization. Avoid truncate/create
   side effects before the confined open succeeds.
4. Config invalidation, changed `allowedDirectories`, stale capabilities,
   nonregular paths, missing addon or unsupported OS primitives **deny** the
   restricted operation rather than falling back to the old pathname API.
   Preserve `allowedDirectories: []` only if deliberately and successfully
   loaded; its historical unrestricted behavior is not described as sandboxed.
5. Keep the adapter optional for the *build* only if the product explicitly
   declares nonproduction/unavailable capabilities. In a supported portable
   distribution with configured restrictions, missing or wrong-architecture
   native binaries must cause a hard failure, not silent permission widening.
6. Failures must not leave partially mutated data, leaked descriptors, or
   detached write tasks. Ensure final error messages identify authorization
   denials without disclosing sensitive paths or access tokens.

### API design direction

- `loadPolicy(configRevision, allowedRoots)` -> opaque policy capabilities,
  or a typed denial. Policy state must be immutable for each operation.
- `read(policy, relativeFile, options)` -> opened-object read result.
- `write(policy, relativeFile, contents, mode)` -> confined object mutation;
  explicit rewrite/append semantics remain compatible with T008.
- `mkdir(policy, relativeChild)`, `rename(policy, from, to)`,
  `stat(policy, relativeChild)`, and `list(policy, relativeChild)` must
  provide the same containment guarantees.
- The adapter must document ownership/lifetime of capabilities and resources,
  cancellation and bounded memory. TypeScript must not use the existing
  pathname-based filesystem functions as a fallback on security-relevant paths.

Do not implement this API from the diagram alone. First confirm that cap-std
provides the required guarantees on Windows **with junctions and
case-sensitive directories**, and verify safe handling of Linux mount/symlink
semantics. Reject the dependency or revise the design if the proof fails.

## Implementation sequence and mandatory native gates

**T011-A infrastructure checkpoint (not a security fix):** The new
`test/security/support/controlled-interleaving.js` establishes a deterministic,
bounded checkpoint/interleaving API and disposable inside/outside byte fixtures.
Its four harness self-tests run before packaging in the native Windows/Linux CI
matrix. They validate choreography, error propagation, release on failure and
preservation of unrelated outside bytes. They do **not** exercise JDC's
vulnerable filesystem API, do not prove that the race is mitigated and must
never be counted as an authorization gate. The previously reproduced
vulnerability remains a release blocker. The private adversarial reproduction
will only be published with a verified remediation and an appropriate disclosure
decision. The next requirement is to exercise this harness against the
capability implementation on **both** native systems.

**Windows-specific dependency review:** Before adopting `cap-std`, test
reserved device names including superscript-digit variants, junctions,
reparse points and case-sensitive directories. The upstream advisory
[GHSA-hxf5-99xg-86hw](https://github.com/bytecodealliance/cap-std/security/advisories/GHSA-hxf5-99xg-86hw)
documents a previously patched device-name sandbox bypass; do not select
affected versions or assume that Windows resolution rules match Linux.

- **T011-A — Adversarial harness:** deterministic concurrency tests with
  handshakes/barriers (no timing-dependent probabilistic loops), disposable
  fixtures and exact before/after byte checks. Cover parent-component swap,
  final-component swap, traversal, internal symlinks and outside symlinks.
  Explicitly record whether the original baseline exhibits the failure.
- **T011-B — Capability feasibility:** small Rust/Node-API proof of concept,
  package and load on *both* supported native CI runners. Verify platform
  ABI, Rust toolchain versions, lifecycle script policy, licensing, offline
  startup and memory footprint. No production wiring yet.
- **T011-C — Confined file operations:** refactor the underlying filesystem
  handlers to use the capability adapter. Extend to read, rewrite, append,
  create, rename, list, move, editor, PDF and search paths; audit each handler
  for hidden reopen-by-name behavior.
- **T011-D — Security & compatibility:** the adversarial tests must now
  reject every out-of-bound operation, preserve outside bytes, still permit
  valid in-root access, and pass both native OS matrices. Include config
  changes and failure/recovery, Windows drive/junction spelling, Linux case
  sensitivity and rename/replace races.
- **T011-E — Packaging:** verify the native binaries and third-party
  licenses in the complete ZIP/TAR SHA-256 manifest on each platform and
  exercise a real MCP client from the extracted bundle outside the checkout.
  Repeat independent artifact audit both premerge and postmerge.

**Hard-stop conditions:** any out-of-bound effect, CI failure, missing native
addon, unsupported platform behavior, unreviewed runtime privilege, invalid
license, loss of existing in-root capabilities, or a regression in the T008,
T009 or T010 contracts. Do not waive these by marking tests optional.

## Acceptance scope, performance and release restrictions

The goal is an auditable **application filesystem capability boundary** for
the above operations, not a claim that the entire MCP server is sandboxed.
Terminal/process tools, OpenCode integration and other interfaces with
ambient host access require separate authorization and threat modeling.

The solution must support Windows and Linux native runners, Node 22 minimum
and Node 24 portable runtime, without requiring Rust or a compiler on the
customer's machine. The 8-GB Windows host is a deployment constraint; builds
belong in CI, not on the user's production host. UI and error messages must
clearly distinguish denied, unsupported, unavailable and not-found states.

Until all gates above pass, **T011 is open and JDC must not be described as
production-ready for adversarial filesystem authorization**. No installer,
official release, signing, installed runtime, service, tunnel or gateway
changes are authorized by this document.

## Primary design references

- [cap-std capability filesystem API and platforms](https://github.com/bytecodealliance/cap-std)
- [napi-rs Node-API runtime and native build support](https://napi.rs/docs/introduction/getting-started)
- [Linux openat2(2) RESOLVE_BENEATH / RESOLVE_IN_ROOT](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [Windows CreateFile reparse point and share semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Node.js fs and O_NOFOLLOW flags](https://nodejs.org/api/fs.html)
