# T011 Linux root-admin-owned SQLite candidate observation

**Scope:** #139 non-release Linux kernel-owned file observation. This is **not** an authenticated policy issuer, a trusted SQLite connection or VFS, or permission to perform a filesystem operation.

## Contract

The dedicated service identity must first pass the actual OS kernel checks, including filesystem UID/GID, zero extra capabilities and `NoNewPrivileges`. From a kernel-opened root directory, the code resolves the fixed `/etc/jdc-authority` ancestry using `openat` with `O_PATH | O_DIRECTORY | O_NOFOLLOW`. Ancestors must be root-owned directories without group/other write privileges. The policy candidate name is fixed as `policy.sqlite3`, never supplied by MCP. Its file descriptor uses `O_NOFOLLOW` and must satisfy exact root ownership, dedicated service group, `0640` mode, regular-file type, link count 1, bounded size and the 16-byte SQLite signature. Repeated `fstat` checks require identical device/inode/size across the signature read. The opaque result retains that exact kernel-opened file, exposes a device/inode observation, and can consume it once to read at most 4 MiB of bytes. Repeated fstat checks reject changed inode/size; the opened file cannot be redirected by replacing its original pathname. The existing pinned `rusqlite 0.37.0` `serialize` feature deserializes those bytes into a **read-only in-memory SQLite image**, with no pathname/sidecar opens by the SQLite VFS. The exact v2 schema, epoch, SHA-256 digest and bounded effective policy bytes are verified. The storage layer also forces `PRAGMA query_only=ON`; a real attempted UPDATE is rejected in tests. This data-only observation **cannot become a filesystem grant**. A separate root-admin-owned witness is observed before and after the policy read, and both observations must match the verified policy epoch and digest.

## Required real-host evidence

T011's existing governed Linux native job provisions two distinct nonroot principals on a disposable GitHub-hosted Ubuntu runner and uses the existing `custody_fixture` Rust example to generate a genuine SQLite file. A new mandatory acceptance test confirms the service account with kernel `NoNewPrivs: 1` can observe the root-admin-owned file, while the foreign MCP identity and root identity are denied. The Rust fixture creates a real v2 policy SQLite DB **and a separate exact 40-byte administrator witness**. The service can parse the in-memory policy bytes and match that independently read witness; missing or same-length wrong-digest witnesses deny. It then tests group-writable permissions, transfer of owner to the service, a physical same-inode hardlink, truncated length and final-name symlink replacement. Each attack must return a typed denial and the restored fixture must retain its original SHA-256 bytes. The script refuses non-ephemeral, root-runner or preexisting host state and cleans up its temporary privileged files.

## Real-host policy/witness publication-order acceptance (research only)

The existing ephemeral Linux T011 job now creates two genuine, independently
checked SQLite v2 policy images and two fixed-format root-admin 40-byte
witnesses, at epoch 1 and epoch 2. Only root can install either image or
witness; the service reads both under its independently checked kernel identity.
The experiment tests forward-updated DB with stale witness, forward-updated
witness with stale DB, and an older DB with the new witness: all MUST DENY,
with a valid epoch-2 snapshot succeeding only once both match. It also
documents an **explicit NEGATIVE proof**: restoring both an older policy DB
and its matching old local witness admits the old snapshot again; a locally
matching pair has no independent monotonic property.

The disposable runner uses standard `install` to simulate administrative
state replacements. **These are sequential consistency observations, NOT
crash-consistent publishing operations:** `install` does not demonstrate
atomic updates, durable fsync ordering, concurrent readers, authenticated
policy origin or safe recovery. No production updater or service is installed.

## SQLite auxiliary-file denial for immutable main-image snapshots

The protected Linux policy reader now checks the **fixed** SQLite names
`policy.sqlite3-journal`, `policy.sqlite3-wal`, and `policy.sqlite3-shm`
with `fstatat(AT_SYMLINK_NOFOLLOW)` relative to the existing OS-opened,
root-owned administrative directory descriptor. If any entry exists
(including a symlink), or a lookup fails for a reason other than `ENOENT`,
the candidate is DENIED. The same check runs before opening the SQLite
main image, immediately after pinning the main-image inode, and on both
sides of the snapshot byte read. The reader retains the owned directory
descriptor so it cannot be redirected by renaming a pathname supplied by
a client. The real Linux acceptance script adds one root-owned entry of
each type, and a symlinked journal, and requires denial before restoring
the directory to its no-sidecar state.

This explicitly excludes a **known present** hot rollback journal or WAL
from the supported read-only immutable snapshot contract. It does NOT
prove that a root administrator cannot perform a concurrent unsafe
publication, that main-file bytes are durable across a crash, or that
a missing sidecar means a SQLite transaction was committed. Only an
approved administrative publisher with crash-injection and durable
directory/fsync ordering can establish those guarantees.

## Fixed-name inode revalidation after kernel descriptor acquisition

An OS-pinned file descriptor remains attached to its inode when an
administrator replaces its original fixed directory entry. That can make
a verified snapshot stale even when the observed file still has identical
length and its independent witness matches an earlier generation.

The observer therefore compares `fstat` of the *already opened* file
with `fstatat(AT_SYMLINK_NOFOLLOW)` of the fixed
`policy.sqlite3` name relative to the **same verified directory FD**.
It rejects any missing, symlinked, multiply linked, different-owner,
different-inode, different-device or different-size named object. This
check is repeated during pinning, before the actual bounded read, after
reading, and after SQLite in-memory validation. A Linux-only Rust test
uses an actual temporary filesystem and an open handle to demonstrate
that a same-size rename replacement, unlink, symlink and hardlink alias
are refused, while a stable singly linked file passes. No client path
is accepted and no second SQLite connection opens by pathname.

This closes the *observed changed final name at those checkpoints*
case; it does not guarantee that a privileged administrator cannot
change the name immediately **after** the last check. Live grants must
still have an approved immutable publication protocol, epoch
revocation and a bound authorization/operation lifetime. The service
remains deny-only until those independent gates are complete.

## Limits preventing release

The now-implemented in-memory SQLite parse does not reopen a pathname and does not require filesystem journal sidecars. However, it is only a bounded **snapshot read**, not an authenticated publisher protocol, policy semantics or a live SQLite write transaction. No protected updater, independently approved effective policy semantics, crash-consistent atomic replacement of an immutable SQLite generation, root-admin witness write/recovery state machine, service replay ledger linkage, session revocation or MCP operation grant has been implemented. An administrator restoring both DB and witness remains undetectable under the selected local-only assurance tier. Existing `E_POLICY_UNAVAILABLE` startup denial remains unchanged. Whole-machine administrator rollback is outside the selected local identity-separation assurance tier.

Keep #124/#139/#148 P0/open, PR #170 DRAFT, `releaseEligible:false`; require Linux native exact-head CI results before claiming hosted acceptance.
