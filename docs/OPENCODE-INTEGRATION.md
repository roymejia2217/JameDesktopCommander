# JameDesktopCommander and OpenCode gateway integration

## Separate sources of truth

The two source repositories are deliberately independent:

- [JameDesktopCommander](https://github.com/roymejia2217/JameDesktopCommander) owns the ChatGPT-facing MCP tools, terminal, Windows UI bridge, OpenCode **client** and Remote Device integration.
- [chatgpt-opencode-mcp](https://github.com/roymejia2217/chatgpt-opencode-mcp) owns the authenticated loopback gateway, allowlisted project aliases, clean/registered Git worktree checks, session ownership and gateway MCP **server**.
- OpenCode is a separate upstream runtime. WinSW service wrappers, installed binaries, local allowlists, credentials and Git trust config are **deployment state**, not additional Git source repositories.
- Secondary worktrees of either Git repository are not new independent sources of truth.

Ordinary JDC file/terminal tools do not require the OpenCode gateway. The OpenCode tools use only administrator-enrolled **aliases**, not caller-supplied working directories.

## Pinned source compatibility gate

`contracts/opencode-gateway.json` pins an exact Git commit of the gateway. On every JDC pull request and main push, Required CI checks out that immutable commit with credential persistence disabled and runs `test/contracts/gateway-surface.test.js`.

The test parses real TypeScript source using the installed TypeScript compiler API. It verifies the gateway's `registerTool` names exactly match the reviewed protocol list and the JDC adapter's `callGateway` names. Any source-ref change or unexpected tool name fails the gate and requires a deliberate compatibility review.

**Scope:** This is a source-level MCP tool-name compatibility check. It is **not** proof that every payload schema, authentication setting, event stream, process, installed build, or session behavior is production compatible. Keep repository unit tests and real-host E2E admission/rollback independent. Do not mark this gate as full deployed compatibility.

## Deployment provenance requirements

For every production rollout, independently record:

1. JDC remote `main` SHA, isolated compiled source SHA, build/packaging evidence, executable SHA-256, process PID and exact running command. Do not assume the source of `main` is the running binary.
2. Gateway remote `main` SHA, isolated compiled source SHA, `dist/http-cli.js` digest, WinSW service working directory, service executable path and PID.
3. OpenCode version, service identity and loopback binding; **do not disclose** tokens, full secret-bearing command lines or protected configuration contents.
4. Gateway project allowlist and the separate protected OpenCode `GIT_CONFIG_GLOBAL` trust-file hashes. Record accepted alias names and identities without printing secrets.
5. Verified backups and rollback targets for each affected component; restart only services owned by the changed component.
6. Authenticated health, loopback-only endpoints, unauthenticated HTTP 401, registered/clean worktree, rejected dirty/unregistered alias, real read-only task, empty diff, and session continuation across gateway-only restart.

Do not auto-enroll new directories because a prompt mentions them. A Git `safe.directory` trust entry does not replace gateway worktree admission. Do not use wildcard Git trust or clean/stash/reset a user's checkout.

## Release distinction

A successful GitHub build means **source accepted by CI**. Only a provenance-checked, reversible installation and real-host smoke means **runtime accepted**. JDC and gateway must be released and rolled back independently.

Historical read-only acceptance (2026-10-08) used JDC runtime `cf47811` and gateway runtime `e5e3aeb19910a6da9274aed226d826889ce2c61a`. Later integrated source commits differ: JDC `053b84671e0e631d7228ec52f3f533c8fba0f2e0` and gateway `0176b5780a7037d5637b7e75ff1a650fae386570`. These are **snapshot references, not assertions of present deployment state**.

Remaining gates for full integration closure: versioned input/output schemas, cross-repository runtime protocol E2E on pinned binaries, immutable artifact hashes, and a confirmed JDC rollout with rollback. Keep the integration governance issue open until those are proven.
