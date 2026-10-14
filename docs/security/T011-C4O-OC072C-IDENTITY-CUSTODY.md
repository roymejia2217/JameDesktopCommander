# T011 C4o OC-07.2c — Owned SCM identity evidence boundary

**Stage:** experimental, pending protected PR/CI and postmerge.
**Release:** `releaseEligible: false`, SCM terminal `Stopped`, no authorization.
**Tracking:** [OC-07 issue #80](https://github.com/roymejia2217/JameDesktopCommander/issues/80).

## Defect and scope

OC-07.2b retained copies of validated normal and restricted group SID
records, but did not include an owned copy of the SCM process `TokenUser`
SID. The Windows identity check previously returned only a Boolean. Future
independent review cannot safely depend on a borrowed native SID pointer
from a destroyed `GetTokenInformation` buffer.

This increment changes that private observation boundary, **not** the
identity authority or SCM exit policy:

- `token_user_matches_service` queries `TokenUser` using the already
  opened process-token handle and checks the full SID is within the native
  query allocation before `EqualSid` compares it against the resolved
  `NT SERVICE\\JameDesktopCommanderAuthority` SID.
- Only when the kernel-provided SID **matches** does the function copy its
  validated bytes into a private, owned `Vec<u8>`. An identity mismatch
  remains `TokenFinding::IdentityMismatch` (SCM code 2); missing or
  corrupt evidence remains a failure (SCM code 5).
- The private `VerifiedScmTokenSnapshot` receives that owned SID and a
  separate copy of the resolved expected service-account SID. Its
  categorization rejects incomplete, structurally invalid or unequal
  identity copies as `Unverifiable`, before privilege/group policy.
- The independent C4g identity preflight still uses the same shared
  kernel-issued Windows token comparison with its **own** handle. The
  protected SCM owns exactly one process-token handle for all observations.
- No public getter, debug formatting, serialization, filesystem writer,
  network connection, IPC endpoint or release/package change is added.

## Evidence and TDD

Rust TDD initially failed because the new snapshot identity fields were
absent. Regression tests now reject an altered SID and truncated expected
SID. The existing forged and truncated native `TokenUser` pointer tests
remain mandatory. Source contracts verify `EqualSid`, copy-after-match,
single-handle SCM use, private evidence custody and unchanged denial
mapping. Windows Rust 1.91.1 tests, Rustfmt, Clippy and focused Node
contracts passed locally before submission; protected hosted SCM and
postmerge gates remain separate mandatory conditions.

## Nonclaims and next steps

This snapshot is **only an in-process observation prerequisite** and is
not yet a complete confidential token-evidence receipt. The repository is
public. No full token identity/privilege/group inventory may appear in
unencrypted GitHub Actions logs or ordinary artifacts. A subsequent OC-07
export must independently establish a trusted recipient, standard pinned
encryption tool, authenticated one-shot service-to-collector handoff,
commit/binary/OS provenance, adversarial non-admin tests, and bounded
retention and cleanup before any evidence leaves the process. There is
no approved privilege allowlist. Independent OC-07.3 review, policy
custody, authenticated IPC, native C5 I/O, adversarial D and release E
are not eligible to be bypassed.
