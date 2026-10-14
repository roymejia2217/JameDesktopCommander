# T011 C4o / OC-07.2d — Unambiguous native SCM group SID custody

**Stage:** isolated security hardening, pending protected PR and CI.
**Release:** `releaseEligible: false`; SCM remains terminal `Stopped`.
**Tracking:** [OC-07 issue #80](https://github.com/roymejia2217/JameDesktopCommander/issues/80).

## Defect and invariant

OC-07.2b retained owned copies of kernel-issued normal/restricted group
SID records, but neither the native `TOKEN_GROUPS` iterator nor the
private evidence classifier explicitly rejected repeated canonical SID
bytes within an individual group inventory. Different pointers can
hold identical SID bytes. A future independently reviewed token record
must not silently accept duplicated, ambiguous entries with either
matching or conflicting attributes.

This increment uses the Rust standard library `HashSet`; it adds no
dependency or new native service API.

- `RawInfo::sid_groups` first proves the complete SID lies within the
  bounded native `GetTokenInformation` allocation. It rejects duplicate
  *canonical SID bytes* before passing the group's SID to downstream
  native OS comparisons or building the owned snapshot.
- `VerifiedScmTokenSnapshot::classify` independently requires a unique
  SID inventory in each of `normal_groups` and `restricted_groups`.
  The lists are checked separately: it is not an error for an individual
  SID to be present in both lists, as their semantics differ.
- Duplicates, malformed group SIDs, structurally contradictory attributes
  and other invalid token evidence remain `TokenFinding::Unverifiable`
  (SCM code 5). No privilege baseline or group authorization is granted.
- All data still originates from the service's **single** native token
  handle and remains private in memory. No changes to public MCP tools,
  service DACL, Windows host installation, tunnel, running/STOP state,
  IPC, disk I/O or release flags.

## Adversarial verification

- TDD RED: a synthetic `TOKEN_GROUPS` buffer containing **two distinct
  non-overlapping memory allocations with identical, individually valid
  SID values and attributes** was initially accepted. Another test
  changed the owned snapshot to duplicate a normal or restricted SID,
  and found the classifier had accepted it.
- TDD GREEN: both the native parser and the private classifier reject
  the ambiguous inventories; a matching SID across **different** group
  classes remains valid. Existing bounded pointer, privilege inventory,
  user identity and SCM terminal tests remain required.
- Focused Windows Rust 1.91.1, Rustfmt, Clippy `-D warnings`, Node
  SCM contracts and diff checks passed locally before commit. The
  complete Husky pre-push, protected GitHub Actions Windows SCM test
  and postmerge checks must pass independently before acceptance.

## Outstanding security gates

The GitHub repository is public. No token identity, raw SID, group
inventory or privilege name may be written to ordinary public CI logs
or unencrypted artifacts. This slice does **not** implement an evidence
export channel or claim full provenance. Before OC-07.2 capture is
allowed, independently verify an offline encryption recipient and
documented standard cipher, authenticate a single-use SCM-to-collector
handoff, bind evidence to the tested binary/commit/service instance,
enforce narrow ACLs and finite retention, and prove adversarial
non-admin denial. OC-07.3 independent least-privilege review remains
blocked until confidential real-token evidence is available. Protected
policy custody, authenticated IPC, native handle-bound C5 operations,
adversarial D, and release E are separate unapproved milestones.
