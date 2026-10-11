# T011-C1 — Bounded native byte capability operations

**Status:** DRAFT implementation slice, **not integrated in JDC production**.
**Baseline:** `c99347adb0dfea1a5c46f72525adbc09bc181fc2` — independently accepted T011-B postmerge on native Windows/Linux.

## Scope and contract

Extend the isolated `RootCapability` test addon with binary-safe
`readBytes(relative)` and `writeBytes(relative, Buffer, mode)`. Both use
`cap_std::fs::Dir` anchored relative opens, never Node's pathname reopen.

Accepted write modes are explicitly `rewrite` and `append`. Reject invalid
modes and oversized buffers **before** any file creation/truncation. Limit
synchronous reads to 32 MiB + one detection byte, fail rather than truncate,
and refuse writes larger than 32 MiB. Keep exact binary bytes (including NUL
and invalid UTF-8), not text/Buffer conversions through JS strings.

The cap-std root constructor still accepts an ambient path **for disposable
tests only**. Do not expose it through the MCP tool catalog; no production
file handlers use this addon. Tests must pass the real Windows/Linux native
matrix with Node 22.19 and Node 24, including external symlink/junction
denial, parent/absolute traversal, invalid modes, oversized read/write and
outside-byte sentinel invariants. No deployment, publication or runtime
packaging is authorized.

## Explicit limitations and gates

This is a **synchronous prototype**. It can block Node's event loop; its
32-MiB limit is not a general-purpose content-size contract. JDC production
reads/writes for large PDFs, DOCX/Excel, images and other file types require
a separately proven async/streamed, cancellable and bounded design.

Before replacing any handler, T011-C must implement a trusted config-scoped
capability factory with immutable authorization snapshots, expiry and
close-on-change; enforce fail-closed missing-addon and invalid-policy states;
and prove rename/reparse/symlink race confinement under deterministic
interleaving. Production `allowedDirectories: []` is a deliberately
unrestricted configuration, **not** a sandboxed root policy.

## Existing pathname reopen inventory (security-sensitive)

- `src/tools/filesystem.ts`: `readFileFromDisk` obtains a validated
  pathname then `getFileHandler(...).read(...)`; `readFileInternal` calls
  `fs.readFile`; `writeFile` invokes a pathname-based handler.
- `createDirectory`, `listDirectory` and `moveFile` call `fs.mkdir`,
  `fs.readdir`, and `fs.rename` on previously validated path strings.
- `readMultipleFiles`, `searchFiles` and the alternate search manager
  can reopen or recursively traverse pathnames after authorization.
- `getFileInfo` performs `fs.stat`; `writePdf` uses `editPdf` and
  `fs.writeFile` against previously validated pathname strings.
- `src/tools/edit.ts` and `src/utils/files/factory.ts` dispatch to file
  type handlers which may inspect and reopen paths. Every handler and its
  dependencies must be migrated without a pathname-based security fallback.
- Directory UI workspace/render helpers, PDF source insertions and
  process/terminal integrations require distinct call-path audits; no
  claim of full sandboxing is made for ambient process tools.

**Release block:** Until the entire authorized filesystem call graph uses
the approved confined native boundary (and T011-D/E pass), the previously
reproduced JDC TOCTOU remains OPEN. No green tests in this PR may be described
as proof of a production fix.
