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

**Still required before release:** approved Windows/Linux principal and
storage-custody threat model; concurrent alias creation and final-component
swap controls with actual verified attacker interleavings; real Windows and
Linux Node 22/24 native acceptance; #124 N-API ownership/Miri resolution;
#139 protected policy, revocation and all MCP handler migration; unsigned
research binaries must never be packaged as a production capability.
