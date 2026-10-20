# T011-C native OS primitive decision and release blockers

**Source audit:** protected `main` `9ba0a9a73904fd2d7d676814d18e165d2e02b851` (2026-10-20).
**Issue:** [#139](https://github.com/roymejia2217/JameDesktopCommander/issues/139).
**Status:** Architectural decision for a **non-shipping experimental addon**. Not a filesystem confinement or release acceptance.
**Primary sources:** `native/capability-probe/src/secure_root.rs`,
`native/capability-probe/src/lib.rs`,
`native/capability-probe/Cargo.toml`,
[T011-C5](T011-C5-NATIVE-NAMESPACE-SWAP.md) and
[consumer inventory](T011-C-HANDLER-ACCESS-INVENTORY.md).

## Decision: keep the existing audited-library candidate, with a hard release gate

Use [Bytecode Alliance `cap-std`](https://github.com/bytecodealliance/cap-std)
(`=4.0.3` in the prototype) for handle-relative child operations.
Linux trusted-root acquisition uses kernel `openat2` via
[`rustix`](https://github.com/bytecodealliance/rustix)
(`=1.1.5` in the prototype).
Windows acquisition uses official Windows file-handle primitives through
[`windows-sys`](https://github.com/microsoft/windows-rs)
(`=0.61.2` in the prototype).
The Node bridge currently uses pinned
`napi=3.14.2`, `napi-derive=3.6.12`.
**None** is approved for production simply because it is established tooling.
Its exact version and OS behavior must pass the gates below.

Do not replace them with homegrown path checks, repeated `realpath`,
path-prefix comparisons, an arbitrary shell command, or a new native library
chosen without equivalent evidence. No direct privileged SCM interface is
allowed as a shortcut around Node-API ownership review (#124).

## Root acquisition: observed source and proof boundary

| Platform | Implemented primitive | Positive source observation | Unresolved before shipping |
| --- | --- | --- | --- |
| Linux x64 | `openat2(anchor="/", relativeRoot, DIRECTORY\|CLOEXEC, RESOLVE_BENEATH\|RESOLVE_NO_SYMLINKS)` | `secure_root.rs` rejects nonabsolute and lexical parent/curdir components; a single kernel resolution produces the retained `Dir`. Unavailable `openat2` returns an error; there is no `realpath` fallback | Kernel/version support, mount replacement and namespace transitions, final object identity under concurrent mutation, kernel error mapping |
| Windows x64 | Open each absolute path ancestor with `FILE_FLAG_BACKUP_SEMANTICS\|FILE_FLAG_OPEN_REPARSE_POINT` and `FILE_SHARE_READ\|FILE_SHARE_WRITE` (without `FILE_SHARE_DELETE`); reject reparse attributes and retain the last directory handle | `secure_root.rs` validates absolute Disk/UNC prefixes, denies device/verbatim and drive-relative forms, checks each opened object is a directory and not a reparse point | Intermediate and final junction races, case-sensitive directories, alternate Windows namespaces, UNC/network-provider differences, handle flags and access-rights under real-host adversarial operations |

The root path is supplied by trusted policy; opening it does **not**
authenticate who supplied the policy, its revision, or its owner. An opened
handle is not a security principal. Service-token/SCM custody remains separate
and blocked by #80.

## Child operation decision at the current prototype

| Operation | Current native source | Candidate judgment / remaining invariant |
| --- | --- | --- |
| Read bytes/text | `Dir::open`, capped synchronous `Read` | Candidate confined read; 32 MiB limit is prototype-only. A production parser must use authorized bytes and bound memory/cancellation |
| Rewrite/append | `Dir::open_with`, `write_all` | Candidate same-root write; unproven transactional replacement, durability and cancellation. Successful confined open alone is insufficient to guarantee outside-byte or no-partial-effect invariants |
| Create directories | `Dir::create_dir_all` | Candidate root-relative recursion; test intermediate link/junction and concurrent mutation |
| List entries | `Dir::read_dir`; reject non-UTF8 names, cap entries at 4096 | Candidate bounded enumeration. Define behavior for concurrent churn and unsupported names; never follow children by ambient paths |
| Move within root | `Dir::rename(from, &sameRoot, to)` | Candidate same-root only. Cross-root or cross-device move must return a typed denial or explicit unsupported result until separately reviewed |
| Metadata | `Dir::symlink_metadata`; reject symlink/reparse/special entries | Metadata path must remain confined; a preflight metadata check followed by a separate destructive operation is not by itself a race proof |
| Remove file / empty dir | `Dir::remove_file`, `Dir::remove_dir` preceded by metadata inspection | Deliberate, nonrecursive operations. Test final-component replacement, link semantics and exact in/outside effects before accepting |
| Policy lifecycle | TypeScript snapshot/generation code plus isolated native root | Not connected to MCP handlers; policy provenance, reload, revoke, stale generation and error taxonomy require full integration acceptance |

The current `RootCapability` uses a `Mutex<Option<Dir>>` and synchronous
methods. This proves neither bounded event-loop latency nor cancellation.
Never call its synchronous prototype on unrestricted document sizes or
sensitive production handlers. Native byte conversions and allocations
must have explicit size ceilings before parsing ZIP, PDF, Excel or images.

## Threat-model gaps not closed by the existing C5 swap test

1. **Final file component and aliases.** An attacker may change the final
   name between metadata and mutation. Hard links can alias data outside an
   allowed root without traversing outside it; handle-relative pathname
   confinement alone is not a hard-link/OS-account isolation guarantee.
   Establish the supported hard-link policy and tests before exposing
   mutation under a restricted policy.
2. **Kernel and filesystem differences.** Linux mount namespaces, bind mounts,
   filesystem types and Windows junction/reparse variants are not certified
   by a single directory-swap fixture. Use real supported Windows/Linux
   runners and fail closed if a required primitive is unavailable.
3. **Write transactions.** Immediate `truncate(true)` and append are not
   atomic file replacement. Define whether compatibility requires an
   atomic replace, how partial failures are handled, the commit point, and
   how readers and cancellation observe it. No success claim before
   outside sentinel and target-state invariants pass.
4. **Format adapters and ambient access.** ExcelJS, PDF libraries, PizZip and
   image tools must process bytes already obtained through the verified
   capability. Any nested PDF insert source, linked resource or search
   subprocess pathname must be independently authorized or explicitly
   unsupported in restricted mode. A temporary file opened by ambient
   pathname is not a substitute for capability confinement.
5. **Revocation and mixed requests.** Capture one immutable, authenticated
   configuration generation per operation. Policy changes close/revoke
   capabilities. Independent source/destination paths are not assumed to
   share a root or generation.
6. **Principals and packaging.** The addon must be tied to provenance-checked
   native binaries on both platforms and Node 22.19/24. No automatic fallback
   to unconfined JS, unknown-ABI binary or privileged SCM service.

## Required next implementation and acceptance (unmet)

- Obtain a reviewed decision on #124 before loading this N-API wrapper in
  production. Miri's failing receiver model is a real model failure, not
  permission to suppress diagnostics and not yet a proven production exploit.
- Define typed restricted errors `DENIED`, `UNAVAILABLE`, `UNSUPPORTED`,
  `NOT_FOUND` and protocol-compatible UI rendering. Explicitly loaded
  `allowedDirectories: []` is intentionally unrestricted, **not** a
  restricted sandbox; invalid or stale restricted policy fails closed.
- Complete the MCP call graph and replace all restricted path-opening
  consumers with handle-bound operations. Do not ship a partial migration:
  `read_file`, `read_multiple_files`, `write_file`, `edit_block`,
  `write_pdf`, `render_workspace`, directory operations and all relevant
  search paths must be reconciled first.
- Run deterministic attacks with actual native operations and real MCP
  dispatch on Windows and Linux, covering intermediate/final component swaps,
  reparse/alias controls, symlinks/hardlinks, a retained outside sentinel,
  changes during long work, and negative cases. If a test setup fails to
  perform the mutation it demands, the test is inconclusive/FAIL, not PASS.
- Run locked Rust/Node verification (including Miri, Clippy, cargo-deny,
  CodeQL), exact build identity, signed commit, full portable candidate
  inventory, independently reviewed provenance, clean-client acceptance
  and rollback. Do not activate `releaseEligible` or SCM privileges.

**Decision outcome:** existing `cap-std` + platform primitives are the
leading implementation candidate; no alternative library has been approved
and **no production integration is authorized**. The remaining conditions
are explicit security acceptance obligations, not a completion claim.
