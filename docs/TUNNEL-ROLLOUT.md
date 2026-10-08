# Windows tunnel runtime cutover: preflight and rollback requirements

## Trust boundaries

The active Desktop Commander stdio process is a child of the OpenAI
`tunnel-client.exe` launched by a Windows Scheduled Task. Terminating the
JDC Node process directly can sever the authenticated remote control plane.
A separate JameDesktopCommander Tunnel Restart Supervisor task is installed,
but its existing worker verifies startup health **without automatically
restoring the previous tunnel profile** after a failed configuration cutover.

Do **not** switch a production profile until transactional rollback is
implemented and verified from outside the tunnel process tree.

## Read-only YAML preflight

`planWindowsTunnelRuntimeProfileCutover()` in
`src/platform/windows/tunnel-cutover-preflight.ts` is a pure function. It
accepts profile text and explicitly reviewed absolute old/new runtime entry
paths and allowed root. It enforces exactly one `mcp.commands[0].command`
reference, a single pinned-worktree-style entry path inside the trusted root,
valid non-ambiguous YAML and semantic equivalence of all other YAML fields.

It returns original and proposed SHA-256 hashes, a one-change count and a
candidate YAML representation **in memory only**. It performs no filesystem
writes and does not touch running processes. The proposed profile can retain
private configuration and must **never be printed or logged**.

The directory suffix is a label, not proof of commit identity. A release
controller must independently validate the complete Git SHA, clean detached
worktree, canonical realpaths, native module hashes and output catalog.

## Independent production rollout prerequisites

1. Confirm exact Git commit/CI success and reproducible candidate build,
   including all relevant `dist` modules (not just the unchanged index shim).
2. Capture running JDC/tunnel PID ancestry, the exact registered task/profile,
   and native tunnel-client health without exposing any credentials.
3. Back up the real protected YAML profile and verify its SHA-256 and ACL.
4. Validate the staged candidate YAML using the read-only preflight and the
   actual tunnel-client schema. Reject stale hashes, symlinks, or ambiguous
   multiple runtime references.
5. Implement an **external supervisor** that stages/replaces the profile
   atomically, restarts the registered task, checks the new process identity,
   command, artifact digests and full readiness/control-plane-poll status.
6. On any failure, the same external supervisor must restore the verified
   original profile, restart the known-good tunnel and report the rollback
   outcome persistently, without relying on the broken tunnel for recovery.
7. Only after real-host acceptance should the old runtime be retired.

An approved source-level compatibility contract is not deployment acceptance.
The JDC and private OpenCode gateway deploy independently. Neither GitHub
source checks nor a successful preflight authorize an unverified outage.

This document covers the **read-only preflight phase** of JDC issue #37.
It does not claim the automated cutover or rollback has been implemented.
