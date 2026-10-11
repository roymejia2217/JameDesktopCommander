# Internal portable distribution candidates (Windows and Linux)

## Classification

This pipeline produces **unpublished test candidates**, not official JDC
releases or single-file native JDC binaries. Each candidate contains a copy
of the official Node.js executable for its runner, JDC's transpiled JavaScript,
locked production \`node_modules\`, and the licensing files required for the
Node runtime and inherited upstream JDC source. The payload remains
platform-specific: Windows x64 and Linux x64 are built and checked on their
respective native GitHub runners.

This first slice does **not** claim that JDC's native Windows UI Bridge or
Remote Device/tunnel is bundled, nor that all optional browser/UI/native tool
features have passed isolated installation or real-host acceptance. The
present service and gateway deployment is not modified.

GitHub's raw directory artifact upload omits dotfiles and does not guarantee
preservation of executable permissions after extraction. Each native candidate
is therefore stored as a **single TAR file inside the temporary GitHub
Actions artifact ZIP**. The TAR includes hidden dependency metadata and
retains Linux executable permission bits. Its contents are independently
rechecked against the full manifest after a GitHub artifact upload/download
round-trip, and the extracted Node/ripgrep runtime is smoke-tested again.
The native TAR transport depends on the runner's standard tar utility.
A green pre-upload staging verification alone is not sufficient.

GitHub Actions retains each candidate for only seven days under
\`UNPUBLISHED-jdc-portable-win32-x64\` and
\`UNPUBLISHED-jdc-portable-linux-x64\`. No installer, npm publication,
GitHub Release asset, tag, signing step or automatic update is created.
The existing Release Please workflow remains unchanged.

## CI gates and payload contract

The file \`scripts/distribution-candidate.mjs\` uses only supported Node.js
built-ins; it has five explicit operations: \`build\`, \`verify\`, \`smoke\`, \`archive\`, and \`roundtrip\`.
Its final outputs are written exclusively under a fixed
\`RUNNER_TEMP/jdc-candidate-<platform>-x64\` staging directory.

The native CI matrix installs from \`package-lock.json\` with lifecycle
scripts disabled, compiles the project, validates the MCP tool contract,
runs negative tests of the candidate format, removes development
dependencies, and then stages the resulting payload.

Each candidate includes:

- \`runtime/node.exe\` (Windows) or \`runtime/node\` (Linux): the exact
  executable used by the corresponding Node 24 CI job
- \`NODE-LICENSE\` copied from the installed Node distribution; build
  fails if that license cannot be found
- \`dist/\`, \`node_modules/\`, \`package.json\`, \`package-lock.json\`,
  and the inherited \`LICENSE\`
- \`candidate-manifest.json\`: \`schemaVersion: 1\`, immutable
  \`releaseEligible: false\`, source SHA, run ID, attempt, target, exact Node
  version, runtime executable, entrypoint and a sorted SHA-256/byte-length
  inventory of **every other file**

Verification independently traverses the staged tree, rejects symbolic
links, junctions and other nonregular filesystem entries, rejects
case-insensitive path collisions, validates all manifest entries and
recomputes the entire inventory. Nothing is checked merely by pathname.
It rejects source/runner mismatch, missing or extra files, and any changed
byte. \`node_modules/.bin\` command symlinks are not part of the runtime
payload. A candidate must remain \`private: true\` and keep existing
upstream ownership metadata until rebranding is separately reviewed.

The smoke gate runs the **packaged** Node executable, checks the packaged
entrypoint's JavaScript syntax, locates the bundled ripgrep from within
the payload, rejects any system fallback outside that payload, and runs
that native ripgrep to establish architecture-level executability.

## Explicit limitations

- A Node executable plus JavaScript modules is a **portable runtime
  bundle**, not a standalone single-file JDC native binary. Windows
  native UI Bridge remains an independent build path.
- The current Node setup selects the actively available Node 24 patch
  level. Its exact version and executable bytes are recorded in the
  manifest, but **byte-identical builds across dates are not guaranteed**.
  Locking a reviewed runtime patch and independently validating the
  entire binary supply chain is a separate release gate.
- Source SHA, binary SHA-256 and native CI smoke do not prove the process
  that is running on an operator's Windows machine came from this bundle.
- The source build/CLI/test suite, real full MCP handshake, clean-machine
  installation, user state migration, recovery after network loss,
  uninstallation, signed binaries, least-privilege tool execution and
  rollback still require **dedicated acceptance**.
- The existing \`@wonderwhy-er/desktop-commander\` and
  \`io.github.wonderwhy-er/desktop-commander\` identifiers belong to
  upstream; this candidate must not be advertised as an official
  independently branded JDC distribution. Resolve package identity,
  licenses, third-party notices and release namespace ownership first.
- Do not infer isolation from \`--no-onboarding\`, an OpenCode prompt,
  filesystem path admission or a Dockerfile. Runtime permissions
  require provider-side/OS-level evidence.

## Remaining gates toward a public first release

1. Accept this native Windows+Linux packaging matrix and download its
   ORIGINAL CI artifacts for independent manifest and binary-byte audits.
2. Exercise the packaged server's full MCP initialization and tool
   discovery without developer dependencies or an existing installation.
3. Package and validate Windows UI Bridge and document Linux UI
   parity/supported exclusions; audit native dependencies and licenses.
4. Prove clean-host install/uninstall, persistent configuration,
   recovery/reconnect and safe rollback on both operating systems.
5. Establish JDC-owned repository/package/bundle identifiers, immutable
   versioned release provenance and approved signing/verification.
6. Only after those controls pass, authorize a governed Release Please
   tag and publish Windows/Linux assets with downloadable hashes.

The public integration issue #32 was closed administratively; its
historical deployment and compatibility acceptance criteria must not
be inferred to have passed solely from the issue's state.

## Native packaged MCP end-to-end gate

After uploading and downloading each native candidate, CI restores its TAR to
an isolated path outside the checkout. `scripts/portable-mcp-e2e.mjs` uses the
**official MCP SDK client shipped in the candidate itself** to spawn the
**candidate's own Node executable** and compiled JDC server over stdio.

The gate negotiates MCP initialization, checks advertised capabilities,
discovers the tool catalog with uniqueness and selected-name requirements,
lists UI resources, reads one actual UI resource, and lists prompts.
The server receives a fresh temporary working directory and configuration,
with telemetry disabled and a minimal child environment. It is closed and
the temporary state is deleted even after failures.

This verifies packaged protocol initialization and read-only catalog/resource
operations on native CI runners. It does **not** exercise arbitrary tool calls,
OS sandbox boundaries, clean-host installation, UI Bridge inclusion, service
startup, real-host identity, upgrade/recovery, or rollback. Artifacts remain
`releaseEligible: false` and unpublished.

## Native fixture tool-call acceptance (T008)

The same portable MCP client additionally exercises six real protocol
`tools/call` requests against a single file created inside its disposable
working directory. The native Windows and Linux jobs must prove:

- `list_directory` exposes the test fixture and `read_file` returns its
  original content.
- `write_file` without an explicit `mode` is rejected on a nonempty file
  and preserves its exact bytes (data-loss regression).
- Explicit `mode: rewrite` and `mode: append` both succeed and their
  resulting on-disk UTF-8 bytes match independent filesystem reads.
- A final `read_file` observes both rewritten and appended content.

The test uses the MCP SDK's real `callTool(params, resultSchema, options)`
API. It does not use mocked handlers, a developer Node runtime, host services
or a production configuration. Temporary state is cleaned up after the client
closes. Passing does not demonstrate OS confinement or safety of untested
tool handlers, nor does it authorize a release.

## Case-sensitive access boundary acceptance (T009)

**Security regression:** lowercasing every filesystem path in
`src/tools/filesystem.ts` made distinct directories such as `allowed/` and
`ALLOWED/` compare equal on Linux. With `allowedDirectories: [allowed]`,
a real packaged MCP client could read and overwrite `ALLOWED/` despite the
restriction. The failure was reproduced against an independently audited
Linux candidate with entirely disposable files, and reproduced as denied
after preserving case in the path comparison.

The native acceptance test runs through the actual packaged MCP server
using the bundled Node and official SDK. After the existing fixture tests,
it configures exactly one allowed directory and verifies two authorized
read/write operations. It then requires denials for direct sibling reads and
writes, a traversal path, a directory link escaping the allowlist, and a
new-file write through that link. The Linux runner additionally proves a
case-different directory is distinct and rejects reads and writes there.
Independent filesystem reads assert that none of the denied writes changed
outside bytes. A failed denial is a hard CI failure.

This intentionally preserves path case for all platforms; explicit
case-sensitive matching may conservatively reject some differently cased
Windows path spellings rather than inadvertently authorize a distinct path.
Case preservation, symlink resolution and `allowedDirectories` do **not**
constitute an OS sandbox, prevent races after validation, or constrain
independent process-execution tools. Those require separate review and
OS/provider-level enforcement. This test does not authorize publication.
