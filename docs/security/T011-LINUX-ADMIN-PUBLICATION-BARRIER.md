# T011 - Linux root-admin publication intent barrier (non-release)

**Scope:** #139, experimental Linux reader-side barrier plus **root-only durable publication-begin primitive**. No authenticated policy-image publisher, commit, rollback recovery or finish/clear operation is provided. The native service binary remains deny-only (`E_POLICY_UNAVAILABLE`), and the helper grants no filesystem rights.

## Reader invariant

The administrator-controlled fixed directory `/etc/jdc-authority` is anchored through verified root-owned parent directory file descriptors, and the service executes under a separately verified nonroot kernel identity with `NoNewPrivileges`.

A fixed entry named `.policy-publish-inflight` is reserved as a persistent, administrator-owned publication intent. The reader uses standard `fstatat(AT_SYMLINK_NOFOLLOW)` relative to the **already opened trusted directory descriptor**, and **DENIES if anything occupies the name** (regular file, symlink, directory, malformed object), or when the lookup fails for any error other than `ENOENT`. It never interprets marker contents or receives a path from the MCP caller.

The check occurs during directory acquisition, independently during SQLite candidate opening, before and after the bounded pinned-inode SQLite read and witness reading, and before returning a matched epoch/digest policy snapshot. The process-local epoch monitor poisons itself on a failed observation. This prohibits accepting a coherent-looking old pair while a persistent intent is present, and prevents such a failed observation from reactivating that same monitor after the marker disappears.

## Governed acceptance

The new `linux_policy_publisher::begin_fixed_publication()` checks the actual root real/effective UID and GID, opens the fixed root-owned `/etc/jdc-authority` directory through validated `O_RDONLY|O_DIRECTORY|O_NOFOLLOW` descriptors, creates an **empty, root:root 0600** marker with `O_CREAT|O_EXCL|O_NOFOLLOW`, validates the created inode and calls `sync_all` on the marker followed by `fsync` on the directory. A second begin cannot override an existing marker, and any error after creation deliberately leaves fail-closed state behind. No path, policy bytes or marker-removal operation is exposed. A tiny CI-only Rust example invokes this primitive as the real root user; it is not packaged or registered as a service.

The existing mandatory T011 Linux CI runner (ephemeral GitHub-hosted only) provisions distinct `root`, `jdc-authority` and `jdc-mcp-client` identities. After installing a real root-owned policy and witness, the acceptance script demonstrates:

- The service principal cannot create the intent in the root-owned directory.
- Root's actual publisher-begin primitive creates the fixed intent durably; a repeated begin fails due to `O_EXCL`, and even otherwise matching policy and witness bytes are denied.
- Removing the intent allows a **new** data-only snapshot observation.
- A symlink in place of the marker also denies; removal restores the original bytes.
- The prior same-process sticky revocation/epoch-transition, hardlink, sidecar and namespace protections remain mandatory.

Native Linux unit tests also use real filesystem entries under a temporary directory to verify file, missing entry, and symlink transitions. These are not mock stat structs.

## Administrator publisher requirements still missing

The now-implemented root-only **begin** primitive supplies exclusive marker creation and filesystem sync. A future independently authenticated updater still must ensure the identity and provenance of its approved source bytes, and then prepare a new immutable root:service 0640 generation without exposing half-written content, and publish files through documented OS atomic-rename and durability ordering. It must clear the intent only after every policy/witness generation has been validated and durably committed; failure must leave an intent requiring independent administrative recovery. Concurrent writer serialization, reentrant reader races, source authenticity, exactly monotonic epoch advancement and safe fail-closed recovery after each possible crash window all require adversarial acceptance. This increment **does not implement or prove** those writer guarantees.

Because local rollback of BOTH policy and witness plus removal of intent can still evade a new process, no hardware-/remote-backed monotonic guarantee is claimed. A reader's last check does not hold a lock against a privileged future publisher: **this is not in-flight authorization linearization**, and it cannot grant/retain a filesystem capability.

**Status:** `releaseEligible:false`. Keep #124/#139/#148 OPEN, #170 DRAFT, and the installed Windows runtime, `main` and OS services unchanged.
