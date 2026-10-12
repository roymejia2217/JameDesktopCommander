# T011-C5 — Native handle-bound directory operations and actual namespace-swap proof

**Status:** Experimental Rust/Node-API implementation, **not yet connected to
JDC production filesystem handlers**. Baseline protected main:
`f2946705949854ebd55b3cfa7a1594e31f5fc36f`.

## Direct TOCTOU remediation work, not another policy shim

The existing T011-C1 native capability handles cover bounded binary reads and
writes. Real JDC also performs `createDirectory`, `listDirectory`, and
`moveFile` with path-based `fs.mkdir`, `fs.readdir`, and `fs.rename`
after `validatePath()`. These remain actual production vulnerabilities.

This slice extends the isolated native `RootCapability` with:

- `createDirectory(relative)` backed by **`cap_std::fs::Dir::create_dir_all`**.
- `listDirectory(relative)` backed by **`Dir::read_dir`**, not host ambient
  `std::fs::read_dir`. Refuse non-UTF8 names and directories above 4096
  entries rather than silently truncating.
- `moveRelative(from, to)` backed by
  **`Dir::rename(from, &same_open_dir, to)`**. This first slice supports
  same-root moves only; multi-root or cross-device moves are not silently
  substituted by unconfined pathname copying.

Every operation locks the same native opened `Dir`, rejects a closed
capability, resolves children relative to the handle, and never returns an
authorized absolute pathname for JavaScript to reopen. No shell, IPC, file
handler or ambient `std::fs` operations are introduced.

## Adversarial native OS proof

A separate `test/security/capability-namespace-swap.test.cjs` runs with
**actual compiled Rust** under Node 22.19 and Node 24 on **both**
`windows-2025` and `ubuntu-24.04`.

The test:

1. Creates a disposable, non-sensitive allowed root and an outside root
   with an exact binary sentinel, and opens a native root capability.
2. Checks the original legitimate nested path, then actually renames its
   intermediate directory and installs a symlink (Linux) or junction (Windows)
   targeting the outside directory. The test asserts the swap **actually
   succeeded**; a denied/unsupported swap fails rather than giving a fake
   PASS for confinement.
3. Calls real native `readBytes`, `writeBytes`, `createDirectory`,
   `listDirectory` and `moveRelative` through the swapped component. Every
   call must be rejected, **without modifying the outside sentinel, creating
   outside directories, moving a source outside, or stealing an outside file**.
4. Removes the attacker-controlled link, restores the valid in-root directory
   and verifies that legitimate native directory and binary file operations
   still work, including exact bytes.
5. Separately checks legitimate create/list/move functionality, relative
   traversal denial and the closed-handle lifecycle.

All test fixtures are disposable and checked before cleanup. No installed
runtime or user data is accessed. This test holds the attacker-controlled
namespace at its swapped state *while native operations execute*; it does not
prove safety against every sub-operation timing race inside cap-std or across
threads and processes. More adversarial interleaving (including final file
symlink/hardlink, rapid swaps, volume reparse points and cancellation) remains
mandatory in T011-D.

## Remaining release-blocking implementation

This code is deliberately part of a separately tested native addon and is
**not loaded or packaged by production JDC**. It therefore does not yet
remediate the real `src/tools/filesystem.ts` calls or the rich format,
editor, search and UI workspace handlers. A following implementation must
integrate an independently authorized, authenticated and revoked native
capability owner, ship verified native binaries on both platforms, and migrate
**every filesystem entry point without a path-based fallback**.

There is no credible way to claim the production TOCTOU is fixed with a green
native test alone. `allowedDirectories: []` remains the historical
unrestricted configuration and is not represented as a protected root.
Terminal and process tools retain separate ambient privileges outside this
file-tool confinement model.

Premerge and postmerge gates: supported Windows/Linux native builds,
`cargo-deny` and exact Cargo.lock, tests under both supported Node versions,
governance/CI/CodeQL/Codespell, independently rehashed original binary and
full portable ZIP/TAR inventories, exact source commit provenance, and
`releaseEligible:false`. Any failed swap test is a real FAIL, not
silently skipped or treated as OS safety proof.

No new release, deployment, native shipment, service, tunnel or gateway is
authorized by this incremental implementation.
