# Linux-first portable MCP acceptance (development gate)

**Status:** No public release. Linux x64 portable candidate is internal and
`releaseEligible: false` until the repository's protected gates pass.
This document does not authorize installing the candidate into an operational
environment or processing sensitive SENAE data.

## Existing portable capability

The `Unpublished Portable Candidate` workflow builds a Linux x64 archive on
Ubuntu 24.04 containing its own Node.js executable, production dependencies,
compiled JDC, a byte-inventory manifest and provenance data. After upload,
download and independent integrity verification it extracts the candidate
**outside** the Git checkout and runs a genuine client over MCP stdio with
the official MCP SDK. The gate already validates initialization, tools/list,
resources, prompts, read/write behavior on disposable fixtures, allowed
directories and negative path cases. No dependency on an installed Node binary
is assumed at run time.

## New Linux-specific acceptance checks

The unpacked **same candidate runtime** now additionally must:

1. Run under the non-root, disposable GitHub-hosted Linux user.
2. Invoke `start_process` through a real MCP `tools/call` using the
   official `/bin/sh` and a fixed `printf` command, and receive its exact
   marker. No terminal UI, system service or network port is started.
3. Invoke `computer_inspect` with `action: health` and receive the
   explicit `WINDOWS_REQUIRED` error. Windows UI Automation functionality
   is **not** falsely advertised as supported on Linux.
4. Preserve all existing packaged MCP, runtime hashes, access-policy and
   outside-byte sentinel checks without skipping Windows tests.

The additional tools are checked against the actual packaged executable and
real protocol transport, not a local TypeScript module or a mock server.
The process execution smoke deliberately confirms functionality, **not OS
confinement**: `allowedDirectories` is an application filesystem policy and
does not restrict `start_process`. Use a dedicated, least-privileged OS user
and independently reviewed isolation for any high-trust deployment.

## Linux delivery critical path

- **Dependency hygiene:** PR #146 supplies patched `markdown-it` and must
  receive independent review and merge before further integration; this
  PR is based on its exact commit only to keep runtime audit clean.
- **Linux minimum:** the extracted archive must pass integrity,
  initialization, discovered tools, real process launch, filesystem fixture
  contract and explicit unsupported-UI rejection on Ubuntu. A local Linux
  acceptance still has to demonstrate a clean user installation, persistence,
  migration, restart/reconnect, rollback and user-visible MCP availability.
- **Security:** T011 #139 and hard-link object isolation #148 are
  independently open. The experimental native capability is blocked by #124
  N-API ownership and #80 service authority. No adapter or native test may
  be skipped to publish a Linux variant. Do not process SENAE credentials
  or protected files with this unapproved candidate.
- **Desktop capabilities:** Linux `computer_inspect` requires a separate
  accessibility/portal implementation and real Wayland/X11 desktop tests.
  A successful CLI + MCP acceptance is not Linux GUI parity.
- **Distribution:** source-package identity and signing, clean Linux user
  install/uninstall, supported distribution list, GUI support scope,
  rollback and provenance still need approval. Never publish upstream
  package identifiers as JDC-owned packages.

**Result interpretation:** a green CI means the tested Linux basic MCP
contract works on that runner. It is not evidence of Linux production
readiness, a live ChatGPT tunnel, browser UI automation or T011 completion.
