# T011 C4o — OC-07.2b prerequisite: owned SCM group observations

**State:** experimental pre-export security slice, pending protected PR and CI.
**Authorization:** permanently deny-only, `releaseEligible: false`.
**Tracking:** [issue #80](https://github.com/roymejia2217/JameDesktopCommander/issues/80).

## Defect / risk

OC-07.2a retained private, copied enabled privilege names and a few derived
group flags; it did not retain the actual normal and restricted group
inventories. Windows `TOKEN_GROUPS` consists of pointers into the variable-
length `GetTokenInformation` buffer, so storing the native
`SID_AND_ATTRIBUTES` items in a longer-lived snapshot would create stale
or dangling native pointers. The future confidential evidence contract
must never serialize or trust such pointers.

## Increment

- `RawInfo::copied_sid_group` accepts a SID only after the existing
  **complete SID-in-buffer bounds proof**, and copies the exact canonical
  SID bytes to a private `OwnedSidGroup { sid: Vec<u8>, attributes: u32 }`.
  No caller-provided SID can bypass the kernel token observation.
- The existing normal and restricted group enumerations now produce owned
  vectors in the **same SCM process**. Windows `IsWellKnownSid` and
  `EqualSid` still operate on the original bounded, live kernel buffer,
  before that buffer is dropped. The snapshot receives no native SID
  pointers and does not implement `Debug` or serialization.
- An enabled-and-deny-only group attribute combination is structurally
  contradictory and is rejected. All copied groups are rechecked for exact
  SID layout and conflicting attributes before categorization; incomplete
  or corrupted evidence produces `TokenFinding::Unverifiable` (SCM code 5).
  No new privilege or group allowlist is added.
- The SCM entrypoint, terminal codes, public MCP API, service DACL,
  release gates and installed runtime are unchanged.

## Tests

TDD RED: the independent buffer mutation test could not compile without
`copied_sid_group`. TDD GREEN tests that the copied bytes remain stable
after the originating kernel buffer is changed, forged out-of-range group
pointers are rejected, and conflicting attributes cannot be classified
as reviewed evidence. A Node source contract checks that **both** group
inventories are copied and kept private, while the existing single-handle
contract remains mandatory. Local Rust tests, Rustfmt, Clippy and Node
contracts must pass, followed by Windows native SCM CI and full postmerge.

## Nonclaims / security stop conditions

This slice does **not** encrypt, persist, transmit or review the group
inventory. It does **not** prove group semantics beyond the stated native
bounds and attribute-consistency invariants. The full token inventory is
sensitive and must not be written to GitHub Actions logs or ordinary
unencrypted public artifacts.

A future confidential OC-07.2 export still requires an independently
verified offline decryption recipient, pinned standard cryptographic
tooling, authenticated one-use handoff between the SCM and evidence
collector, provenance tied to the tested service binary and protected
commit, adversarial non-admin tests, retention limits and cleanup.
Do not derive authorization from the CI runner identity, environment
strings or an observed Windows default privilege. OC-07.3 independent
least-privilege review, policy custody, authenticated IPC, C5 filesystem
I/O, D adversarial validation and E distribution are separate gates.
