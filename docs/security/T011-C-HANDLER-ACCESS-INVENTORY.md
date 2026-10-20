# T011-C — Path-dependent MCP filesystem consumer inventory

**Status:** Design and migration inventory only. **No production mitigation**.
**Issue:** [#139](https://github.com/roymejia2217/JameDesktopCommander/issues/139).
**Source revision:** `9ba0a9a73904fd2d7d676814d18e165d2e02b851`
(protected `main`, 2026-10-20).
**Gates:** [T011 capability boundary](T011-FILESYSTEM-CAPABILITY-BOUNDARY.md),
[#124 N-API ownership](https://github.com/roymejia2217/JameDesktopCommander/issues/124),
[#80 SCM privilege review](https://github.com/roymejia2217/JameDesktopCommander/issues/80).

This records **confirmed source-level path operations**, not a completed
call-graph proof or a claim that a specific race is exploitable in every
consumer. Existing `validatePath()` followed by separate pathname I/O
does not bind a filesystem object to its authorization decision. This inventory
does not disclose adversarial interleaving details.

## Verified MCP entry points and consumers

| MCP surface | Routing observed at source revision | Native-bound migration requirement |
| --- | --- | --- |
| `read_file` | `handlers/filesystem-handlers.ts:78` -> `tools/filesystem.ts:424` -> `utils/files/factory.ts` -> format handler | Confined read, metadata and format detection; no post-authorization filename reopen |
| `read_multiple_files` | `handlers/filesystem-handlers.ts:280` -> `tools/filesystem.ts:665`; separate validation and read per input | Per-input scoped authorization, independent errors and output ordering |
| `write_file` | `handlers/filesystem-handlers.ts:343` -> `tools/filesystem.ts:630` -> format handler | Confined rewrite/append/create with explicit commit/cancellation semantics |
| `create_directory` | `handlers/filesystem-handlers.ts:409` -> `tools/filesystem.ts:707` -> `fs.mkdir` | Handle-relative hierarchy creation; preserve recursive behavior only if proved safe |
| `list_directory` | `handlers/filesystem-handlers.ts:425` -> `tools/filesystem.ts:713`; recursive `fs.readdir` at ~723 | Scoped traversal with bounded depth and no re-opening moved ancestors |
| `move_file` | `handlers/filesystem-handlers.ts:459` -> `tools/filesystem.ts:780` -> `fs.rename` | Confined source and destination; deny unproved cross-root moves |
| `get_file_info` | `handlers/filesystem-handlers.ts:502` -> `tools/filesystem.ts:911` -> pathname `fs.stat` | Confined stat and format metadata reads |
| `write_pdf` | `handlers/filesystem-handlers.ts:529` -> `tools/filesystem.ts:999` -> pathname reads/writes | Confine target, input PDF and each insert source separately |
| `render_workspace` / file preview | `handlers/filesystem-handlers.ts:256` dispatches to `getFileInfo`, listing or reading | Share the same data boundary; presentation is not a separate authority |
| `edit_block` | `handlers/edit-search-handlers.ts` -> `tools/edit.ts:414`, including `performSearchReplace` at ~116 | Read/edit/write against authorized objects; preserve line endings and fuzzy semantics |
| `start_search` | `handlers/search-handlers.ts` -> `search-manager.ts:59` | Search all descendants under a bound root, not a checked pathname |
| Search continuation / termination | `handlers/search-handlers.ts` manages sessions and results | Bind search session to policy generation, cancellation and approved root authority |

Source anchors are informative for this exact revision, not stable API contracts.
The list is a **confirmed minimum**. Other dispatch routes, tool aliases,
process tools and indirect consumers require separate full coverage review.

## Reopen-by-name sites confirmed beneath those entry points

- `src/tools/filesystem.ts`: `validatePath` ~221;
  `readFileInternal` -> `fs.readFile` ~609;
  `writeFile` -> handler write ~649;
  recursive `listDirectory` -> `fs.readdir` ~723;
  `moveFile` -> `fs.rename` ~783;
  `searchFiles` recursion -> `fs.readdir` ~860;
  `getFileInfo` -> `fs.stat` ~914;
  `writePdf` -> `fs.writeFile` ~1018 and ~1048.
- `src/tools/edit.ts`: `performSearchReplace` first validates a pathname
  and then calls `readFileInternal` ~145; the `edit_block` dispatcher
  selects a format handler after pathname validation ~425.
  Review every writeback and replacement count path before migration.
- `src/utils/files/factory.ts`: format routing selects DOCX, PDF, Excel,
  image, binary or text handlers; the binary detection is content based.
  Format selection must not implicitly open an unrestricted pathname.
- `src/utils/files/text.ts`: pathname `fs.open` ~54, ~295, ~465;
  pathname `fs.readFile` ~103, ~147; writes at ~78/~80;
  `getInfo` -> `fs.stat` ~85.
- `src/utils/files/image.ts`: pathname reads ~40,
  writes ~57/~59 and stat ~64.
- `src/utils/files/excel.ts`: ExcelJS `workbook.xlsx.readFile(path)`
  and `writeFile(path)` are independent pathname operations (e.g.,
  ~44, ~129, ~181, ~235); additional `fs.stat` calls exist.
  Verify supported **buffer-based** parsing/serialization APIs and
  memory bounds before selecting a replacement.
- `src/utils/files/docx.ts`: independent `fs.readFile`,
  `fs.writeFile` and `fs.stat` (~519, ~608, ~648, ~716, ~732).
  Keep ZIP parsing and edits separate from filesystem authority.
- `src/utils/files/pdf.ts`: PDF parsing calls accept a pathname;
  PDF edits invoke `editPdf(path,...)` and `fs.writeFile`.
  `src/tools/pdf/manipulations.ts:21` directly reads a string
  pathname, unlike its buffer input branch. Require byte-buffer
  input/output across the PDF processing stack.
- `src/search-manager.ts:70-84`: authorizes a root pathname and then
  invokes an external ripgrep process. Other branches traverse with
  `fs.readdir`, `fs.stat` and `fs.readFile` (~460-631).
  Merely passing a validated path to ripgrep, or changing its working
  directory, does **not** establish handle-bound containment.
- `src/tools/pdf/markdown.ts`: source image loading can use
  `fs.readFile(source)` (~268); separate Chromium download/cache
  paths (~116-181) are runtime-internal. Classify user-controlled
  local resource paths independently from trusted internal cache
  policy; do not automatically apply the same authorization model.
- `src/tools/improved-process-tools.ts`: writes temporary code and
  launches a child process. This is an **ambient execution** surface,
  not an instance of the scoped filesystem capability guarantee.
  Document its distinct trust and isolation requirements.

## Contract to settle before implementation

1. Distinguish user-supplied filesystem locations, application-owned
   internal files, remote URLs and process execution. None acquires
   authority simply because another layer checked a string.
2. Expose an opaque, immutable policy snapshot with a generation and
   verified root capability. Every operation must use a capability
   from the same generation. Policy invalidation denies pending work.
3. Define owned byte input/output, bounded streaming, metadata,
   directory enumeration, creation, atomicity requirements and
   cancellation; document when atomic writes cannot be guaranteed.
   The current nine-method experimental native interface is a
   feasibility baseline, **not** an accepted production API.
4. Route specialty format processors through authorized bytes or
   explicitly proven handle-compatible interfaces. Libraries that
   can only reopen a pathname require an architectural resolution,
   not an unconfined temporary-file fallback.
5. Search must not spawn a process with ambient access to user
   filenames and then claim the capability boundary applies.
   Until a verified contained-search strategy exists, restricted
   search must be denied or explicitly reported unavailable.
6. Retain legitimate UX behavior (read offsets, image payloads,
   PDF page output, DOCX/Excel edits, recursive listings, search
   pagination and per-path errors) under the new boundary.
   Preserve the established semantics of an intentionally loaded
   `allowedDirectories: []` policy; never describe it as sandboxing.
7. Represent `DENIED`, `UNAVAILABLE`, `UNSUPPORTED` and
   `NOT_FOUND` distinctly, without leaking secret root paths.
   Missing/mismatched native binaries and invalid restricted policy
   snapshots must fail closed with no pathname fallback.
8. Before changing runtime, resolve the independently tracked
   N-API receiver ownership and FFI lifetime blocker (#124).
   Do not enable privileged SCM authority without #80.

## Required verification matrix (not yet executed for this inventory)

| Operation class | Minimum adversarial acceptance |
| --- | --- |
| Reads, metadata, format probing | Parent/final component mutation, links and reparse points, exact outside-byte invariance |
| Rewrite, append, create, edit | Same confinement; preserve legitimate byte content, encoding, cancellation and commit behavior |
| Source/destination and PDF imports | Each path independently authorized; cross-root policy and replacement semantics explicit |
| Directory recursion and search | Policy revocation mid-operation; no descendant escape; bounded work and descriptor consumption |
| Format-specific I/O | Native Windows/Linux coverage for text, binary, images, Excel, DOCX and PDF |
| Distribution | Node 22/24, Windows/Linux, clean-extraction MCP client, native ABI, license and SHA-256 provenance |

**Test status for this documentation slice:** source read-only inspection;
no RED/GREEN, native, CI or packaging test is claimed for this change.
This document adds neither handlers nor confinement. A true T011-C
completion needs a verified full MCP dispatch/call-graph audit, native
safety resolution, deterministic tests against production-bound
operations, and independent postmerge acceptance.

## Suggested implementation slicing

1. Finish the dispatch/indirect-consumer matrix and specify typed
   errors, immutable policy generation, root/capability ownership,
   lifetime and asynchronous cancellation.
2. Resolve #124, or independently approve a maintained and verified
   alternative boundary; no speculative production wiring.
3. Implement a confined byte/metadata/directory layer behind tests.
4. Migrate text, binary, images, multi-file and editing operations;
   then Excel, DOCX and PDF with authorized byte handling.
5. Resolve search and secondary-resource paths without ambient
   pathname fallback.
6. Run deterministic native attacks on actual handlers, then clean
   portable candidate acceptance. Independently review postmerge.

**Release gate:** BLOCKED until all T011-C/D/E obligations pass.
