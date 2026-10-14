# T011 C4o OC-07.1 — SCM privilege inventory integrity gate

**Stage:** experimental local slice, pending CI, protected PR and postmerge.
**Release:** prohibited. `releaseEligible: false`. SCM terminal Stopped,
never Running. Tracking: [T011 OC-07 issue #80](https://github.com/roymejia2217/JameDesktopCommander/issues/80).

## Verified baseline and deficiency

The actual ephemeral Windows SCM process in [Native probe 115678062396](https://github.com/roymejia2217/JameDesktopCommander/actions/runs/38510630394/job/115678062396)
reported `E_SCM_PRIVILEGE_BASELINE_UNREVIEWED` (service-specific
terminal code 3). This means its in-process kernel token had at least one
enabled privilege not yet approved. **That categorical result does not
identify any names or authorize a default allowlist.**

Previously, the `TOKEN_PRIVILEGES` array reader bounded the count and
variable-length buffer, but skipped disabled entries without verifying
their LUID uniqueness or attribute flags. It resolved names only for
enabled entries. Duplicate native LUIDs or unsupported attribute bits
could thus be silently ignored before token classification.

## Narrow security change

`validated_enabled_privilege_indices` is a pure Rust function that
requires no more than 128 records, validates the complete 64-bit LUID
(low and signed high parts), disallows duplicate LUIDs even if disabled,
and rejects all undocumented/unsupported `Attributes` bits.

Accepted Windows flags in this structural layer are
`SE_PRIVILEGE_ENABLED_BY_DEFAULT` (0x1), `SE_PRIVILEGE_ENABLED`
(0x2), and `SE_PRIVILEGE_USED_FOR_ACCESS` (0x80000000).
`SE_PRIVILEGE_REMOVED` (0x4) and other bits are rejected for a
listed token entry, not silently discarded. Enabled means the ENABLED
bit is set; default/used bits by themselves are not approval.

The Windows reader validates the entire bounded native array before
name resolution. It resolves **every** listed LUID through the
documented Windows `LookupPrivilegeNameW`, including disabled entries.
Missing, empty, malformed, unresolvable or duplicate resolved names
are a `TokenUnverifiable` error. Only after all entries are validated
does the classifier receive the names for currently enabled privileges.

## Evidence and verification

- TDD RED: Rust E0432 for absent native-independent privilege
  inventory validation function and record type.
- TDD GREEN: duplicate LUIDs including disabled, high-part mismatch,
  invalid/removal flags, documented flag combinations, empty arrays,
  complete native name-resolution failure, duplicate names and empty
  resolved names.
- Native OS-only acquisition still uses the same single SCM process-token
  handle. No new dependency, environment override or public token output.
- Rustfmt, Rust 1.91.1 tests, Clippy `-D warnings`, and SCM Node
  contracts are local prerequisites; full Windows/Linux native, GitHub
  protected governance and postmerge CI remain mandatory.

## Explicit nonclaims and next work

This change **does not capture, publish, log or approve** actual privilege
names or group inventories. Future OC-07.2 must first establish an
independently protected, transient evidence destination and trusted
provenance, confidentiality, retention and cleanup contracts within the
ephemeral runner. OC-07.3 may define a least-privilege policy only
after independently reviewed real token evidence, never from assumed
runner defaults. IPC authentication, protected custody, revocation,
handle-bound production filesystem I/O (C5), adversarial D and
distribution E remain open. All production filesystem operations remain
denied.
