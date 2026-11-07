# T011-C — filesystem handler callgraph and migration gate

**Status:** security review / non-release design inventory. Not a remediation, approval, or production grant.
**Baseline:** PR #164 experimental code tree `9f5e02c5870c587ca073304f4525a3ab16c21950` (local commit `ee6a9ff`).
**Scope:** installed JDC TypeScript MCP request handlers, adapters and native research modules.
**Approval:** none. Issue #139 remains P0 open; issue #124 N-API ownership and #148 hardlinks remain P0.

## Entry boundary and current TOCTOU

`src/server.ts:1609-1673` dispatches file tools to `src/handlers/filesystem-handlers.ts` and `src/handlers/edit-search-handlers.ts`.
`src/tools/filesystem.ts:221` resolves and checks a pathname; subsequent filesystem APIs accept a newly looked-up name.
Validation does not bind either a final file object or all ancestor identities across namespace mutation.
Do not construe an absolute normalized path or a second check as OS authorization.

## Observed operation paths (source anchors; re-audit after each refactor)

| MCP operation | Path from dispatcher toward actual I/O | Required capability contract |
| --- | --- | --- |
| `read_file` | `handlers/filesystem-handlers.ts` -> `filesystem.ts:441,502,505` -> typed `handler.read(path)` | root-bound open and stream/read from the same handle |
| `read_multiple_files` | `filesystem.ts:665-669` -> `readFile(validPath)` -> file adapter | independent bound capability per item; no batch-wide authority reuse |
| `write_file` | `handlers/filesystem-handlers.ts:341+` -> `filesystem.ts:631,649,652` -> `handler.write(path)` | explicit append/rewrite; opened-object checks and byte-safe replace |
| `create_directory` | `filesystem.ts:708-709` -> `fs.mkdir(path, recursive:true)` | per-component handle-relative `mkdir` with policy epoch |
| `list_directory` | `filesystem.ts:713,723,759` -> `readdir(path)` and path revalidation per descendant | handle-bound traversal, no descendant name reopen |
| `move_file` | `filesystem.ts:781-783` -> two path checks, `fs.rename` | bound source and destination parent handles; no cross-root escape |
| `get_file_info` | `filesystem.ts:911-933` -> `fs.stat` and `handler.getInfo(path)` | handle metadata and any content reads bound to same object |
| `edit_block` | `tools/edit.ts:144,425` plus text read/mutate/write; typed adapter edits | read-modify-write conflict and replace semantics, no path reopening |
| `start_search` | `search-manager.ts:70,84,460-631` -> ripgrep/process and direct descendant reads | confined traversal and content reads; external ripgrep requires separate authority proof |
| PDF edits | `filesystem.ts:1004-1048` + `tools/pdf/manipulations.ts:21` | every source and output separately handle-authorized |

## Indirect adapters and secondary routes

`src/utils/files/factory.ts:76-100` dispatches DOCX, PDF, Excel, image, binary and text based on a **path** and content probing.
All invoked handlers must accept a verified object/capability, not independently reopen a path after authorization.
`src/utils/files/text.ts:54,78-85,103,145-147,295,465` opens/stat/reads/appends/writes by name.
`src/utils/files/docx.ts:158-179` bounds the archive via one opened handle, but that handle is opened by name;
its memory budget and ZIP validation are **not** a root capability or permission to reuse pathname writes at `739,848`.
`src/utils/files/excel.ts:274,320,331` does independent metadata I/O; inspect workbook save internals before claiming confinement.
`src/utils/files/image.ts:40,57-64` performs independent reads/writes/metadata by filename.
`src/utils/files/pdf.ts:86,90,104,120` performs filename-backed writes, output writes and stats.
`src/tools/pdf/markdown.ts:116-181,268` mixes internal cache paths with file inputs. Model trust domains separately.
`src/search-manager.ts:559` directly `fs.readFile`s DOCX files and constructs `PizZip` outside the DOCX adapter;
this path needs its own resource-exhaustion review in addition to T011 confinement; adapter budget PASS does not cover it.
`src/tools/improved-process-tools.ts:32,62,83` uses ambient temporary-file I/O for terminal support.
`start_process` and process/terminal tooling remain ambient host execution; filesystem-only isolation cannot be advertised as an OS sandbox.
`src/ui/file-preview/src/directory-controller.ts` and document/editor preview actions reenter MCP file tools;
their calls must use the same policy and error taxonomy as ordinary direct tool requests.

## Native spike: exactly what is and is not demonstrated

`native/authority-service/src/handle_mkdir.rs` uses `cap_std::fs::Dir` relative single-component create and child open.
`native/authority-service/src/canonical_request.rs` decodes C4d values but returns **request data, not a grant**.
Linux peer/session/FD3 observers attest selected properties but do not provision or pin protected roots.
The current native service executable remains deny-only absent authenticated protected policy and dispatch.
Do not enable experimental N-API APIs, allowlist bypasses, or reuse an unverified caller-supplied root handle.

## Platform decision still requiring independent native evidence

**Linux x64:** test anchored `openat`/`openat2` or reviewed cap-std internals against parent/final swaps,
symlinks, bind mounts, renames, writable parent directory races, and persistent handles after rename.
Proof must identify exact kernel/filesystem semantics, flags, service UID/GID and attacker write rights.
**Windows x64:** test cap-std on NTFS against junction/reparse points, reserved device spellings,
case-sensitive directories, hardlinks, renames, ACL mutation and distinct service vs client tokens.
Never infer Windows security guarantees from an Ubuntu-only test or vice versa.

## Non-negotiable integration order

1. Resolve #124: independently review native ownership/liveness, build ABI and FFI boundary; do not silence CodeQL.
2. Resolve the #148 object/content isolation contract with supported OS-principal custody and adversarial hardlink tests.
3. Load an OS-protected, versioned root policy, validate allowed-root identities, and bind its epoch to each operation.
4. Authenticate actual IPC peer and service principals independently; bind each canonical C4d request to policy.
5. Route **all** listed MCP file and editor/adapter/search operations through an opaque native handle backend.
6. Deny restricted operations with a typed unavailable/unsupported/denied error if backend, ABI, policy or epoch is invalid.
7. Retain `allowedDirectories: []` legacy unrestricted semantics only when deliberately configured; do not call it sandboxed.
8. Execute real red-to-green namespace swap and outside-sentinel byte tests on native Windows/Linux, not mocks.
9. Validate bundle-extracted official MCP-client E2E on Node 22/24, cross-architecture failure, rollback and provenance.
10. Require review, exact-HEAD workflows, main merge, postmerge CI and release authorization before deployment.

## Acceptance matrix — must be executable, not a documentation assertion

| Case | Required result |
| --- | --- |
| Valid rooted read/create/list/move | Correct in-root bytes and metadata |
| Parent/final component swap with adversary barrier | Attack actually occurs; no outside effect; denial or bound-object success |
| External hardlink alias before/while mutating | Outside-object bytes unchanged under declared principal/storage model |
| Changed policy during read/write/search | Operation pinned to approved epoch or explicit typed denial; never ambient fallback |
| Missing native module, old ABI, stale/unknown rootRef | Typed fail-closed in restricted mode |
| Explicit rewrite/append vs omitted write mode | Preserve documented bytes; omitted mode must not destroy existing content |
| DOCX/PDF/Excel/image/text adapters | Uniform capability across *all* internal metadata/read/edit/save steps |
| File-preview and nested search reentry | Same policy enforcement as direct MCP request |
| Terminal/process and internal-cache paths | Explicitly outside file-sandbox claim; separately reviewed trust and OS rights |

**Review verdict:** current architecture is **NOT release-eligible**. This is a path inventory and proof plan,
not a guarantee of complete coverage; dynamic imports, indirect adapters, resource previews and future routes
must be checked with static and runtime tests before sign-off. `releaseEligible:false`.
