# T011-C — Filesystem handler callgraph and non-shipping migration decision

**Status:** architecture inventory for independent review, **not** a security
remediation, an accepted native backend, or permission to enable T011.
**Source anchor:** protected `main` at
`9ba0a9a73904fd2d7d676814d18e165d2e02b851` (2026-10-21).
**Existing contract:** [T011 filesystem capability boundary](T011-FILESYSTEM-CAPABILITY-BOUNDARY.md);
tracking [#139](https://github.com/roymejia2217/JameDesktopCommander/issues/139),
[#124](https://github.com/roymejia2217/JameDesktopCommander/issues/124),
[#148](https://github.com/roymejia2217/JameDesktopCommander/issues/148),
[#80](https://github.com/roymejia2217/JameDesktopCommander/issues/80).

## Grounded callgraph: external path authority is not retained

The following line anchors are from the exact source revision above. A path
checked by `validatePath()` remains an ordinary string: it does **not** retain
a pinned directory or file object across subsequent asynchronous I/O. A passed
pathname check must not be described as native object authorization.

| Surface and entry | Present path through implementation | Bound-object gap |
| --- | --- | --- |
| `read_file` / `render_workspace` | `src/handlers/filesystem-handlers.ts:78,124,256-270` → `src/tools/filesystem.ts:424,441` → `getFileHandler` / `handler.read` | `fs.stat` and delegated readers reopen by path. Rendering uses the same reader. |
| `read_multiple_files` | `src/tools/filesystem.ts:665-703` checks each pathname and calls `readFile` again | Revalidation cannot hold an identity across the second open. Partial per-file errors are a distinct result contract. |
| `write_file` | `src/handlers/filesystem-handlers.ts:343-387` → `src/tools/filesystem.ts:630-652` → `src/utils/files/factory.ts:76-103` | Existing-target size check and write are not atomic. `handler.write` performs pathname I/O. Explicit rewrite/append semantics must survive migration. |
| `create_directory` / `list_directory` | `src/tools/filesystem.ts:707-777` | Recursive `fs.mkdir` and `fs.readdir` use names; descendants assembled with `path.join` are not pinned to the initial root. |
| `move_file` | `src/tools/filesystem.ts:780-783` | Source and destination are separately checked strings before `fs.rename`; both parent objects need independent confinement and a reviewed cross-root policy. |
| `get_file_info` | `src/tools/filesystem.ts:910-925` | `fs.stat` and specialized handler metadata may reopen a mutable name. |
| `edit_block` text | `src/tools/edit.ts:116,143-145,203` and `src/tools/filesystem.ts:585,591,609` | Read-modify-write occurs across independent name resolution; verify expected original object/content before committing a replacement. |
| `edit_block` structured | `src/tools/edit.ts:414,425-450,480-485` → factory / handler `editRange` | Excel and DOCX handlers independently open and save pathnames; validation in dispatch does not constrain their later I/O. |
| `write_pdf` / PDF edits | `src/tools/filesystem.ts:998-1048` → `src/tools/pdf/manipulations.ts:20-23,101-121` | Input PDF, optional source PDFs and output name all need separate object-bound authorization; `editPdf` can reopen secondary paths. |
| `start_search` | `src/handlers/search-handlers.ts:13-34` → `src/search-manager.ts:59-84` | `ripgrep` runs as a separate ambient process with an already-validated pathname; cannot assume a native capability owned by Node constrains that process. |
| Search fallback and Office search | `src/tools/filesystem.ts:843-887`; `src/search-manager.ts:389,460-481,559,616-636` | Node recursive fallback and Excel/DOCX search walk or reopen child paths; no native confinement propagates into each descendant. |
| UI directory/document workspace | `src/ui/file-preview/src/directory-controller.ts:192`; `src/ui/file-preview/src/markdown/controller.ts:372-400` | UI calls public list/read/edit tool contracts; cannot grant a UI-origin bypass or treat preview metadata as a filesystem authority. |

### Separate URL/network authority (`read_file.isUrl`)

`src/handlers/filesystem-handlers.ts:111-124` forwards the caller-selected
`isUrl` option. `src/tools/filesystem.ts:566-574` routes that option to
`readFileFromUrl`, **not** to `readFileFromDisk` or `validatePath`.
`src/tools/filesystem.ts:350-403` performs a network `fetch(url)`; the PDF
branch also passes the URL to `parsePdfToMarkdown(url)` for document loading.
Thus, the same public `read_file` tool has two different authority domains.

A file-directory capability **cannot** confine network egress. URL schemes,
destinations, redirects, credentials, response size and download cancellation
require a separate network/egress threat model and review. This inventory
does **not** establish an SSRF mitigation or authorize an unrestricted URL
reader in a restricted deployment. The future T011 adapter must preserve the
distinction, never imply that `allowedDirectories` constrains remote URLs,
and must not silently reinterpret URL inputs as native filesystem paths.

### Specialized read/write adaptors

`src/utils/files/factory.ts:76-103` dispatches among DOCX, PDF, Excel,
image, binary and text handlers. Each branch is relevant:

- Text: `src/utils/files/text.ts:53-64,76-81,99-104,239-242`
  opens, appends, writes and stats names independently.
- Image: `src/utils/files/image.ts:38-60` calls `fs.readFile/writeFile`.
- Excel: `src/utils/files/excel.ts:40-44,79-157,181-235`
  uses ExcelJS `readFile/writeFile` including append and range edits.
- DOCX: `src/utils/files/docx.ts:518-520,572-608,648-716`
  loads archive bytes, transforms them and writes a pathname.
- PDF: `src/utils/files/pdf.ts:28,82-105`,
  `src/tools/pdf/markdown.ts:263-268`; PDF manipulation also reads
  `sourcePdfPath` during operation evaluation.
- Binary classification: `src/utils/files/binary.ts:23-30` may open a
  path before the final handler decision; handler selection itself must not
  become an unconfined pre-authorization read.

These are **observed candidates**, not proof that every indirect execution
path has been enumerated. An implementation PR must update this inventory from
its own exact HEAD and examine all new provider/preview/adapter entrypoints.

## Decision: no shipping adapter migration until prerequisite proofs

1. **Policy modes remain distinct.** Explicit configured roots select
   *restricted* mode; `allowedDirectories: []` currently means
   *unrestricted* (`src/tools/filesystem.ts:174-179`). Policy load failure or
   stale revision is **unavailable/denied**, not a silent empty allowlist.
   Process/terminal/OpenCode have independent ambient authority; they are
   not constrained by this filesystem policy.
2. **Pin authority for one operation.** A reviewed native backend must
   establish the root handle and immutable policy revision, acquire child
   objects relative to that root, retain valid lifetimes through completion
   and release handles deterministically on cancellation/errors. TypeScript
   receives an opaque request-scoped identifier or bytes, never a reusable
   absolute path as authorization proof. No authorize-then-reopen-by-name.
3. **Hard links are an unresolved object boundary.** PR #147 demonstrated
   real outside-byte changes through hard-link aliases on *both* operating
   systems. Handle-relative path containment alone does not establish
   external-name or object-content isolation. Do not replace the RED tests
   with pathname, `realpath`, `nlink` or `O_NOFOLLOW` heuristics. The
   stronger object invariant requires an explicitly reviewed deployment
   principal/storage model and native evidence. If unsupported, restricted
   operations must be denied before mutation.
4. **FFI ownership is a separate P0.** The draft Miri finding (#124) and
   upstream generated receiver ownership cannot be made shipping merely by
   passing JS runtime, CodeQL workflow or native spike tests. Select and
   independently review a proven binding before connecting any handler.
5. **No unmanaged fallback.** If a restricted operation lacks a verified
   backend or a specialized processor cannot accept safely acquired bytes
   and return bytes without reopening, return typed
   `DENIED`, `UNAVAILABLE` or `UNSUPPORTED`; never call the existing
   `validatePath()+fs.*` code on that branch. This document does not
   change production behavior.

## Proposed review order and proof obligations

1. **Contract / identity review:** approve Linux and Windows principal,
   permitted filesystems, hard-link assumptions and object boundary
   (#148/#80). Confirm supported Node-API wrapper ownership (#124).
   Decision must be recorded by an independent security reviewer.
2. **Minimal native vertical:** real read and write on a disposable confined
   root; original out-of-root sentinels byte-for-byte unchanged under each
   adversarial parent/final-component swap and all four PR #147 hard-link
   cases. Prove attack actually occurred. A negative without a successfully
   mounted attacker fixture is inconclusive, not PASS.
3. **Document/structured adapter:** adapt in-memory Excel, DOCX, PDF and
   image encoders to consume authorized immutable bytes and produce staged
   output bytes. Refuse to use library pathname helpers where a confined
   handle cannot be provided. Source PDF/secondary inputs require separate
   grants. Preserve explicit `write_file` mode, no destructive default, and
   exact line-ending semantics for text edits.
4. **Directory/rename/search:** anchored enumeration and root-relative move
   semantics; no unreviewed recursive name traversal or ambient `ripgrep`
   process under restricted mode. Either an independently verified confined
   search path exists or restricted search returns `UNSUPPORTED`.
5. **MCP/UI end-to-end:** exercise the restored Linux/Windows portable
   bundles using the official MCP SDK, not only direct native-module tests;
   cover read, append, rewrite, edit, Office/PDF, list/move/search, denial
   taxonomy, stale policy, unavailable/wrong-ABI addon, cancellation,
   race cleanup, valid same-root positives, and genuine outside-byte
   sentinels. Record the exact SHA, primary CI, native adversarial runners,
   artifact provenance, and required independent reviews.

**Until these decisions and acceptance gates close, T011-C remains
non-shipping.** This is a technical review artifact; it does not alter MCP
tool routing, grant filesystem access, close #124/#139/#148/#80, or authorize a
new release.
