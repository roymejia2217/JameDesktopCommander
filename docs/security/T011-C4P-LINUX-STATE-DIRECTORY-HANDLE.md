# T011-C4p — Linux protected policy directory descriptor preflight

**Status: non-release, deny-only experiment.** No broker, IPC grant,
policy decoding or production filesystem routing is enabled.

## Decision and OS boundary

Use Linux `open`/`openat` with `O_PATH | O_DIRECTORY | O_NOFOLLOW |
O_CLOEXEC`, and inspect the actual retained descriptors using `fstat`.
The path is a fixed packaging contract, `/var/lib/jdc-authority`,
matching the declarative `StateDirectory=jdc-authority` systemd unit.
It is not selected from a C4d frame, Node config, process environment
or other caller-controlled input.

The exported `observe_provisioned_directory()` first verifies the
kernel service identity via `verify_service_identity()`. It refuses
root and zero-group service identities. It then opens `/` and every
intermediate component relative to the preceding owned descriptor.
Missing paths, symlinks, ambiguous component syntax, unsafe owners,
and group/other-writable ancestors deny.

The final directory must be owned by the dedicated service UID/GID
with exact mode 0700 (including no setuid/setgid/sticky bits).
Every ancestor must be owned by root or that UID, and may not be
group- or world-writable. This deliberately rejects `/tmp` even
when a child directory happens to be private; sticky permissions
alone cannot confer trusted policy custody.

The result retains a kernel descriptor in an opaque Rust object.
No API accepts a caller-provided `rootRef`, epoch or directory path
to construct a production grant. The existing native service binary
still exits with `E_POLICY_UNAVAILABLE` after identity preflight.

## Evidence required

- Native Ubuntu tests must pass: valid non-root private directory,
  retained inode identity after original name replacement, and
  rejection of a symlink, `/tmp`, incorrect owner group, wrong mode,
  group-writable ancestor and invalid absolute path.
- The test positive control is an ordinary dedicated temporary
  directory under GitHub runner `HOME`. This proves kernel behavior
  and descriptor pinning, **not** the provisioned `jdc-authority`
  service principal or an independently trusted storage state.
- Windows cannot compile or execute these Linux-only tests; the
  existing T011 Windows CI neither substitutes for nor disproves them.

## Explicit non-guarantees / next integration gates

- The observer does not open a SQLite database using the pinned
  handle: `EpochStore::open_existing(path)` remains a pathname-based
  offline fixture and can still be rolled back by a path-controlling
  principal. A reviewed handle-rooted SQLite/VFS acquisition design
  and actual protected administrator update workflow are required.
- Directory owner/mode checks do not prove trusted policy bytes,
  stop root/CAP_SYS_ADMIN, compromised service identity, malicious
  administrator, mount/bind replacement by a privileged principal,
  unexpected POSIX ACLs or replay after process restart.
- Descriptor acquisition does not authenticate an IPC peer, bind
  a `rootRef` to a caller or supply operation-level revocation.
  `SealedDirectoryGrant` intentionally has no production constructor.
- Do not grant permissions to Node or use a path string returned
  by this code. A future broker must keep authorization, source-root
  acquisition and the complete filesystem mutation in one trusted
  service-owned boundary, with Linux and Windows cross-principal
  adversarial acceptance and external object-content isolation.

**Release verdict:** `releaseEligible:false`; #124, #139 and #148
remain blocking. No service installation or authority activation.
