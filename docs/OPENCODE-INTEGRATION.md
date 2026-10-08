# JameDesktopCommander–OpenCode integration contract

## Ownership and trust boundaries

JameDesktopCommander (JDC) is the public source of the ChatGPT-facing MCP tools and its OpenCode **client**. [chatgpt-opencode-mcp](https://github.com/roymejia2217/chatgpt-opencode-mcp) is a **private**, independently released gateway, owning authentication, project aliases, Git/worktree admission and OpenCode sessions. OpenCode itself is a separate runtime. A Git worktree is not an independent source repository.

Only project aliases are model-visible: neither user prompts nor JDC tools may select arbitrary directories. The gateway validates worktree identity; the OpenCode Windows service identity has its own administrator-controlled Git trust configuration.

## Public contract and two-sided CI

`contracts/opencode-gateway.json` is the **public protocol manifest**. It declares the accepted MCP tool names, loopback transport path, format version and the gateway commit last reviewed by the maintainers. The commit is review provenance, **not** proof that a runner fetched or executed that private gateway source.

**JDC CI** parses its local TypeScript client with the TypeScript AST and verifies that all `callGateway` names match this manifest. It never checks out or executes private gateway source and needs no cross-repository credentials. This is essential because JDC is public and executes CI on pull requests.

**Gateway CI (separate repository)** must check out the public JDC manifest at a reviewed commit and compare all actual gateway `registerTool` names against it. This check belongs in the private gateway CI, which may safely fetch the public contract. Do not supply gateway repository read credentials to public JDC PR workflows. Pin third-party Actions by SHA, and avoid executing downloaded PR code under credentials that can read the private gateway.

The two-sided check only verifies protocol tool **names**. It does not prove request/response schema compatibility, authentication, cancellation, connection handling, or real-host deployment; those require separate versioned fixtures and end-to-end tests. Changes to the manifest or pinned gateway baseline require review and reconciliation in **both** repositories.

## Release provenance and recovery

Record JDC and gateway source commits, their independently built artifact hashes, exact Windows runtime paths, service identities, running process IDs and hashes of protected configuration files. Do not publish secrets, bridge tokens, private source archives or secret-bearing command lines.

For an approved rollout:
1. Preserve the dirty canonical checkouts and build in clean isolated worktrees.
2. Back up the actual protected service configuration and alias allowlist, verifying digests.
3. Verify JDC and gateway versions separately; restart only the owning changed service.
4. Check authenticated health, loopback-only listeners and HTTP 401 for unauthenticated clients.
5. Verify accepted clean worktree and rejected dirty/foreign aliases, real read-only OpenCode execution, empty task diff and continuation after gateway-only restart.
6. Verify rollback and preserve the original runtime until acceptance is confirmed.

A passing repository CI does **not** prove that the production runtime has been deployed. At the October 8 acceptance, the active JDC runtime was still based on `cf47811` and the gateway runtime on `e5e3aeb19910a6da9274aed226d826889ce2c61a`. These are historical observations; do not assume they remain current.

Issue #32 remains open until cross-repository schema/E2E evidence and reversible JDC runtime rollout are complete.
