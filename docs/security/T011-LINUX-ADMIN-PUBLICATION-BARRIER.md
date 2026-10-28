# T011 - Linux root-admin publication intent barrier (non-release)

**Scope:** #139, experimental Linux reader-side barrier plus **root-only durable begin/commit primitives** for a validated immutable SQLite image. There is no approved production policy-source enrollment, root grant issuer, general-purpose recovery or administrative rollback/repair API. The native service binary remains deny-only (`E_POLICY_UNAVAILABLE`), and the helper grants no filesystem rights.

## Reader invariant

The administrator-controlled fixed directory `/etc/jdc-authority` is anchored through verified root-owned parent directory file descriptors, and the service executes under a separately verified nonroot kernel identity with `NoNewPrivileges`.

A fixed entry named `.policy-publish-inflight` is reserved as a persistent, administrator-owned publication intent. The reader uses standard `fstatat(AT_SYMLINK_NOFOLLOW)` relative to the **already opened trusted directory descriptor**, and **DENIES if anything occupies the name** (regular file, symlink, directory, malformed object), or when the lookup fails for any error other than `ENOENT`. It never interprets marker contents or receives a path from the MCP caller.

The check occurs during directory acquisition, independently during SQLite candidate opening, before and after the bounded pinned-inode SQLite read and witness reading, and before returning a matched epoch/digest policy snapshot. The process-local epoch monitor poisons itself on a failed observation. This prohibits accepting a coherent-looking old pair while a persistent intent is present, and prevents such a failed observation from reactivating that same monitor after the marker disappears.

## Governed acceptance

The new `linux_policy_publisher::begin_fixed_publication()` checks the actual root real/effective UID and GID, opens the fixed root-owned `/etc/jdc-authority` directory through validated `O_RDONLY|O_DIRECTORY|O_NOFOLLOW` descriptors, creates an **empty, root:root 0600** marker with `O_CREAT|O_EXCL|O_NOFOLLOW`, validates the created inode and calls `sync_all` on the marker followed by `fsync` on the directory. A second begin cannot override an existing marker, and any error after creation deliberately leaves fail-closed state behind. No path, policy bytes or marker-removal operation is exposed. A tiny CI-only Rust example invokes this primitive as the real root user; it is not packaged or registered as a service.

A separate `commit_fixed_publication(next_image: &[u8])` performs the **second, forward-only phase**. It refuses nonroot UID/GID; validates exact v2 SQLite schema, policy bytes, SHA-256 and strictly higher epoch against the already root-owned policy image and separately stored 40-byte witness. It requires an existing single-link root:root 0600 intent. It stages the next image and derived epoch/digest witness into two exclusively created `root:service 0640` files, fsyncs each staged file and their directory, renames the image then witness using `renameat` with a directory fsync after **each** rename, re-reads the actual final files and revalidates the intent before unlinking it and fsyncing the directory. Existing staged files, a symlink, mismatched old witness, or a lower/equal epoch cause DENY without auto-cleanup. A partial failure may leave a new DB with old witness, but the persistent intent forces readers to deny until independent administrative recovery.

This is intentionally **not** a complete production updater: the source of the next image is passed by the trusted root-side caller, with no separate signature/approval protocol; no resilient operator recovery/resume contract, explicit crash injection or IPC issuer exists. The CI-only example reads a synthetic SQLite fixture through a runner-local path but does not expose such an API from the service.

The existing mandatory T011 Linux CI runner (ephemeral GitHub-hosted only) provisions distinct `root`, `jdc-authority` and `jdc-mcp-client` identities. After installing a real root-owned policy and witness, the acceptance script demonstrates:

- The service principal cannot create the intent in the root-owned directory.
- Root's actual publisher-begin primitive creates the fixed intent durably; a repeated begin fails due to `O_EXCL`, and even otherwise matching policy and witness bytes are denied.
- Removing the intent allows a **new** data-only snapshot observation.
- A symlink in place of the marker also denies; removal restores the original bytes.
- Forward commit from epoch 1 to 2 publishes a genuine root-owned SQLite image plus matching witness and removes the intent after fsync; an epoch-2 snapshot is accepted.
- An existing exclusive staging file denies publication without overwriting it, and the intent remains active; a trusted CI-only cleanup then permits a new attempt.
- An attempted downgrade from epoch 2 to epoch 1 denies and retains the intent until separate root cleanup.
- The prior same-process sticky revocation/epoch-transition, hardlink, sidecar and namespace protections remain mandatory.

Native Linux unit tests also use real filesystem entries under a temporary directory to verify file, missing entry, and symlink transitions. These are not mock stat structs.

## Restricted split-generation recovery

An administrator-controlled power interruption can occur after `renameat`
publishes the new SQLite image, but before the separately staged witness is
installed. The durable intent remains present so every reader denies. The
root-only `recover_after_policy_rename()` can finish **only this provable
split state**, under the fixed kernel-pinned root-owned administrative
directory. It demands an intact root:root 0600 intent, absence of the staged
SQLite image (the final SQLite name must already have been replaced),
absence of all SQLite sidecars, a verified root:service 0640 current policy,
a separately root-owned old witness and a root:service 0640 staged next
witness. The old witness epoch must be nonzero and **strictly lower** than
the current SQLite image epoch; the staged witness must match the exact
effective policy epoch and SHA-256 digest, and must differ from the old
witness. This function accepts no client path or policy bytes.

On a match, the function renames the staged witness, fsyncs the directory,
reopens and verifies the two actual published artifacts, checks that the
same intent inode is still present and only then unlinks the intent and
fsyncs the directory. Failure preserves the intent whenever possible. The
real Linux CI acceptance exercises both mismatched/stale cases (DENY) and
a genuine epoch-2→epoch-3 split recovery (SUCCESS) using independently
root-owned synthetic SQLite fixtures. It is an event-driven, non-release,
privileged acceptance on a disposable runner.

**Explicit limits:** This covers one interrupted state only. It does not
recover a commit stopped before the SQLite rename, after a witness rename,
or after unlinking the intent but before the final directory fsync.
An empty intent does not record an independently signed immutable expected
transition, and neither the resulting pair nor process-local monitor can
detect full offline rollback of all root state. Independent crash injection,
operator-authenticated provenance, secure monotonic witness and in-flight
authorization are still mandatory before production. No automated
clear-all marker or rollback to older permissions is permitted.

## Administrator publisher requirements still missing

The implemented root-only begin/commit protocol supplies an exclusive marker, a strictly forward image+witness transition, staged fsync/rename ordering, and denial of a failed publication. It does NOT establish policy-source signature/provenance, approved semantic authorization, administrative operator authentication beyond root kernel identity, a documented recovery operator for every crash boundary, or a state machine linearized with in-flight native filesystem operations. Concurrency against malicious root processes, crash injection after each file and directory synchronization, power-loss persistence and safe fail-closed recovery after every crash window all require independent acceptance. It cannot be deployed as a complete trusted policy issuer.

Because local rollback of BOTH policy and witness plus removal of intent can still evade a new process, no hardware-/remote-backed monotonic guarantee is claimed. A reader's last check does not hold a lock against a privileged future publisher: **this is not in-flight authorization linearization**, and it cannot grant/retain a filesystem capability.

**Status:** `releaseEligible:false`. Keep #124/#139/#148 OPEN, #170 DRAFT, and the installed Windows runtime, `main` and OS services unchanged.
