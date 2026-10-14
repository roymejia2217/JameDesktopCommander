# T011-C4o OC-06 — Canonical Windows token integrity SID parsing

**State:** Experimental, local verification only until native CI and postmerge.
**Release:** Deny-only; `releaseEligible: false`. No production authorization.

## Defect and scope

The C4o Windows token observer already validates that a native SID pointer
is inside its bounded `GetTokenInformation(TokenIntegrityLevel)` allocation.
However, its former integrity classifier checked the mandatory integrity
authority S-1-16 and read the RID from the **last four bytes**, without
requiring exactly one subauthority. A structurally valid S-1-16 SID with
multiple subauthorities could therefore be interpreted as an integrity
level even though that is not the canonical mandatory label representation.

## Surgical implementation

`token_policy::integrity_sid_rid(&[u8]) -> Option<u32>` is an OS-independent
pure parser. It requires revision 1, exactly one SID subauthority,
exactly 12 SID bytes, the S-1-16 authority and a nonzero integrity RID.
It is deliberately agnostic about any runner-specific integrity level;
it does not approve a level or infer a privilege baseline.

`windows_token::integrity_rid` first validates the kernel-supplied SID
pointer and full encoded length through `RawInfo::sid`, then calls the
pure parser. Any malformed, oversized, truncated, out-of-range or
noncanonical SID returns `TokenUnverifiable` before classification.
The SCM converts missing/invalid evidence into terminal denial code 5.

## Evidence and contracts

- TDD RED: native contract test could not import the absent
  `integrity_sid_rid` function (Rust E0432).
- TDD GREEN: platform-independent tests cover a valid medium-level
  S-1-16 SID, wrong revision/authority, zero RID, no subauthority,
  two subauthorities and truncation. Windows-specific tests cover the
  real native layout and a forged pointer outside the query allocation.
- Node SCM contract requires bounded native parsing and forbids
  choosing the last four bytes as a fallback.
- Rustfmt, Windows Rust tests, Clippy `-D warnings` and targeted
  Node contracts must pass before pushing. GitHub-hosted Windows
  SCM acceptance and full Windows/Linux CI remain separate mandatory gates.

## Nonclaims and blockers

This slice does not change the service account, group/privilege
whitelist, platform APIs, IPC, filesystem access, operating-system
services, installed runtime or release controls. It does not expose
token inventory in public logs. The actual least-privilege
privilege/group baseline has **not** been independently approved.
C5 native production I/O, D adversarial testing and E distribution
remain outstanding. The service must remain `Stopped` and deny-only.
