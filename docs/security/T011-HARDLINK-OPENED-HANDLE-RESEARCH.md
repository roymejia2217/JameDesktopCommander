# T011 / #148 — Opened-handle hardlink research (NON-RELEASE)

**Status:** Draft, isolated security feasibility; NOT approved for shipping.
**Candidate base:** `fec1a516`, `fix/issue148-native-atomic-replace`.
**Scope:** Experimental `native/capability-probe` only; no MCP handler migration.
**Release decision:** `releaseEligible:false`; #124, #139, #148 remain P0.

## Contract reconciliation

The original four adverse cases in `capability-namespace-swap.test.cjs`
require a **DENIED** result for cross-root hardlink read, rewrite, append,
and final-component substitution, with outside bytes unchanged.
Two later positive tests instead required atomic rewrite of that identical
cross-root hardlink to succeed. The same arguments and file identity cannot
simultaneously satisfy these conflicting requirements. The positive
expectations were therefore tightened to require denial **and** byte
preservation at both names. Their assertions about real shared file
identity remain. Independent single-link read/append/rewrite tests retain
legitimate operation acceptance; existing Windows NTFS DACL, integrity,
read-only and temporary-file controls remain required.

## Native guard scope

The pinned, maintained `cap-fs-ext 4.0.3` `MetadataExt::nlink` observes
file metadata from the **already opened handle**, not a pathname preflight.
Known multi-link (`nlink != 1`) and nonregular objects are denied before
read, append or replacement. Existing append targets are opened without
creation, then checked. Missing targets use `create_new(true)` exclusively.

The follow-up `stat_relative` hardlink confidentiality check also inspects a
regular file using a root-relative opened handle before returning its size.
The earlier name-only `symlink_metadata` branch disclosed the size/type of a
cross-root linked sentinel; the new Windows RED fixture reproduced this and
the subsequent native build denied it. Directory metadata remains a separate
name-based, non-release observation, and an inaccessible/read-protected file
may now fail closed rather than returning metadata. This does **not** protect
against a hard link added after the handle check, nor prove origin custody.

Atomic rewrite retains the existing kernel WRITE_DATA authorization and
NTFS DACL/integrity propagation, additionally denying known shared targets.

This is **not proof of origin or complete race safety**. After the link
count snapshot, a same-principal adversary may introduce another alias;
there remains a separate final-name replacement race between checking an
opened handle and publishing a new file. Root confinement does not imply
exclusive inode custody. No global pathname-to-object inventory is claimed.

## Evidence and remaining gates

Initial physical Windows before this change: original four hardlink
adversarial cases 0/4 PASS, with append changing independent outside bytes.
After changes on the physical Windows host: the four original adverse
cases and the complete 17/17 native Node security suite PASS, including
single-link operations and protected NTFS DACL/integrity behavior. Linux CI
and real concurrent aliasing remain UNVERIFIED. Keep all adversarial checks;
do not skip/xfail or lower their assertions to silence contradictions.

### 2026-10-28 additional Windows checkpoint (still non-release)

- RED against the original compiled binary: `statRelative` disclosed
  the size of a real outside hard-link sentinel; the independent positive
  single-link file/directory metadata control passed.
- GREEN after the bounded handle-metadata correction: native security suite
  **19/19 PASS**, including real NTFS DACL and integrity controls; locked
  Rust 1.91.1 build, Rustfmt and strict Clippy `-D warnings` PASS.
- `npm run verify` terminal **370/370 PASS**, TypeScript build and MCP
  synchronization **34/34 PASS** on this older research branch.
- `npm run verify:push` **FAILED** at its mandatory runtime audit:
  **7 findings (4 high, 3 moderate)** in outdated dependencies including
  `body-parser`, `fast-uri`, `ip-address`, `qs`, `zod` and associated
  `puppeteer-core` dependency paths. No audit bypass or forced dependency
  update was applied. Reconcile against current protected `main` in a
  separate, reviewed integration before any merge or release.
- Hosted Linux, Node 22/24 and concurrent attacker alias tests have **not**
  been accepted for this new source revision. `releaseEligible:false`.

**Still required before release:** approved Windows/Linux principal and
storage-custody threat model; concurrent alias creation and final-component
swap controls with actual verified attacker interleavings; real Windows and
Linux Node 22/24 native acceptance; #124 N-API ownership/Miri resolution;
#139 protected policy, revocation and all MCP handler migration; unsigned
research binaries must never be packaged as a production capability.
