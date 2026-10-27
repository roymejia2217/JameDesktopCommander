# T011 Linux root-admin-owned SQLite candidate observation

**Scope:** #139 non-release Linux kernel-owned file observation. This is **not** an authenticated policy issuer, a trusted SQLite connection or VFS, or permission to perform a filesystem operation.

## Contract

The dedicated service identity must first pass the actual OS kernel checks, including filesystem UID/GID, zero extra capabilities and `NoNewPrivileges`. From a kernel-opened root directory, the code resolves the fixed `/etc/jdc-authority` ancestry using `openat` with `O_PATH | O_DIRECTORY | O_NOFOLLOW`. Ancestors must be root-owned directories without group/other write privileges. The policy candidate name is fixed as `policy.sqlite3`, never supplied by MCP. Its file descriptor uses `O_NOFOLLOW` and must satisfy exact root ownership, dedicated service group, `0640` mode, regular-file type, link count 1, bounded size and the 16-byte SQLite signature. Repeated `fstat` checks require identical device/inode/size across the signature read. The result exposes only the observed device/inode tuple and **cannot be converted into a SQLite store or a policy grant**.

## Required real-host evidence

T011's existing governed Linux native job provisions two distinct nonroot principals on a disposable GitHub-hosted Ubuntu runner and uses the existing `custody_fixture` Rust example to generate a genuine SQLite file. A new mandatory acceptance test confirms the service account with kernel `NoNewPrivs: 1` can observe the root-admin-owned file, while the foreign MCP identity and root identity are denied. It then tests group-writable permissions, transfer of owner to the service, a physical same-inode hardlink, truncated length and final-name symlink replacement. Each attack must return a typed denial and the restored fixture must retain its original SHA-256 bytes. The script refuses non-ephemeral, root-runner or preexisting host state and cleans up its temporary privileged files.

## Limits preventing release

This test validates metadata custody of an OS-opened file only. A SQLite VFS may independently reopen its main file and journal sidecars by pathname, and thus **cannot inherit** this descriptor identity merely by passing a filename or `/proc/self/fd` string. No protected updater, approved effective policy schema, authenticated journal lifecycle, separately owned high-water witness/rollback recovery, SQLite read under that exact verified inode, session revocation, or MCP operation grant is implemented. Existing `E_POLICY_UNAVAILABLE` startup denial remains unchanged. Whole-machine administrator rollback is outside the selected local identity-separation assurance tier.

Keep #124/#139/#148 P0/open, PR #170 DRAFT, `releaseEligible:false`; require Linux native exact-head CI results before claiming hosted acceptance.
