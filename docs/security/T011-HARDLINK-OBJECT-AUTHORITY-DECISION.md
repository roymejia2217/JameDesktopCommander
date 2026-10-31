# T011 / #148 — Hard-link object-authority decision record

**State:** PROPOSED / NOT APPROVED / NO-GO. This document does not grant
filesystem authority or close #148, #139 or #124. It is a reviewable
deployment contract for Windows x64 and Linux x64, based on the T011 boundary.
**Baseline:** PR #230 commit `860243c7085b73fe7346dd4eeb8d0a3450dd9901`.

## Invariant and explicit non-guarantees

Restricted authorization must protect **object bytes**, not merely prevent a
pathname from leaving the selected directory. If a file has an authorized name
and an unauthorized hard-link name pointing to the same underlying object,
direct writes, append, truncate and reads must not be considered authorized
only because the in-root name resolves successfully.

The directory handle plus no-symlink or no-mount traversal limits the route
used to open a file. It does not establish where all other hard-link names
reside, which principal created them, or whether an alias was added after
metadata was sampled. In particular, `nlink == 1` is not an origin proof or
an atomic authorization-to-operation primitive.

A privileged service, root account, or filesystem administrator must not be
assumed to be an unprivileged adversary. Conversely, an attacker running as
the same OS account as JDC may be able to bypass directory-only policy.

## Supported deployment decision to review

1. **Default restricted mode:** retain the existing fail-closed native
   authority result, `E_POLICY_UNAVAILABLE`, until policy roots, principal
   isolation, durable replay authority, and object provenance pass acceptance.
   Never fall back to TypeScript `validatePath()` then ambient `fs.*`.
2. **Legacy explicitly unrestricted mode:** preserve its documented behavior
   only when an actual persisted policy explicitly contains `[]` or `/`.
   This mode is *not* sandboxed and must not be represented as secure T011.
3. **New file, never existing inode:** handle-relative `create_new` is
   acceptable only as an experimental building block; reject pre-existing
   names. Review partial writes, crash durability and subsequent aliasing.
4. **Existing-object read:** reject known multi-link files; distinguish that
   defense in depth from a proof that an attacker cannot create a new alias
   after the last check. Absent enforceable object custody, do not issue a
   restricted read grant.
5. **Rewrite/append:** do not authorize in-place mutation of a supplied inode
   without independent object origin and race-resistant ownership guarantees.
   Staging a fresh inode avoids modifying the previously linked inode's bytes,
   but alone does not prove the destination identity at the commit point.
6. **Move, rename and metadata:** require an independently reviewed object
   identity and root-custody decision; do not classify metadata or listing as
   safe just because the pathname is lexically within a root.

These are candidate deployment conditions, not implemented permission checks.
## OS-specific authority requirements

### Windows x64 / NTFS

Microsoft documents that multiple directory names on the **same volume** can
refer to one NTFS file and all such names expose modifications to its bytes.
A path-constrained open does not prevent this. The proposal must prove actual
DACL/owner and service-token separation, target volume identity, final file-ID
and share-mode behavior using *real Windows kernel handles*. Neither the
service SID nor a checked `nlink` count alone proves object custody.

A rewrite primitive (`ReplaceFileW`, rename or equivalent) requires a review
of its replacement-file identity, backup/rollback, streams and DACL behavior.
Do not infer a guaranteed atomic compare-and-replace from its name or from
the existing `cap_std::Dir::rename` wrapper.

### Linux x64 / supported filesystems

`openat2` `RESOLVE_BENEATH` restricts name traversal;
`RESOLVE_NO_XDEV` additionally rejects mount crossings, including bind mounts.
Neither prevents same-mount hard links. `fs.protected_hardlinks=1` restricts
cross-principal creation but does not prohibit hard links to files already
owned by the attacker or readable/writable to them, so it is insufficient
as the sole protection. Measure UID/GID/capability boundaries, mount identity,
file `st_dev`/`st_ino`, link count and storage ownership on an actual runner.
## Required real-kernel acceptance matrix

- Windows NTFS and Linux filesystems, Node 22.19 and supported Node 24:
  genuine known cross-root hard-link aliases reject reads and in-place writes,
  without returning a prefix of restricted data or changing an outside byte.
- Deterministic concurrent alias insertion **after preflight**, during file
  staging and adjacent to the commit/read response. Synchronization must
  prove the attack actually took place; unsuccessful setup fails the test.
- Final pathname swap, parent replacement, same-volume alias, Linux bind
  mounts and Windows junction/reparse crossings. Verify the destination file
  identity as well as exact outside-sentinel bytes and new-file cleanup.
- Legitimate in-root single-link read, create and replace positive controls;
  intentionally unsupported operations return typed denials rather than a
  falsely successful result.
- Restart/rollback, stopped service, stale policy epoch, failed replay claim,
  wrong peer principal and unavailable addon all deny with no ambient fallback.
- No unconditional ignore, no privileged mount capability assumption, no mock
  claimed as a kernel proof. Execute under the documented actual OS principals.
- Full T011-D/E native, packaged and MCP acceptance; independent FFI lifetime
  evidence for #124, before any change to `releaseEligible:false`.

Existing source `replace_existing_file_staged` checks `nlink` before creating
the staging file and renames later without binding the final entry to the
originally observed identity. This is a **known audit gap**, not a claim of
a demonstrated exploit or a completed remediation. Extra rechecks can narrow
a window but cannot close it by themselves.
## Authoritative technical references

- Microsoft: [NTFS hard links and junctions](https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions).
- Microsoft: [CreateHardLinkW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createhardlinkw).
- Microsoft: [ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew).
- Linux manual: [openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html).
- Linux kernel: [fs.protected_hardlinks](https://docs.kernel.org/admin-guide/sysctl/fs.html#protected-hardlinks).

**Release gate:** unresolved. This record documents the security decision
required from the project owner and security reviewer; it neither authorizes
an experimental issuer nor changes any installed runtime.
