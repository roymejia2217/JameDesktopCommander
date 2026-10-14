# T011 C4o OC-05 — Bounded standalone Windows identity preflight

**Status:** experimental, deny-only, awaiting CI acceptance. **Release:** prohibited (`releaseEligible: false`).

## Defect / trust boundary

The standalone C4g Windows `verify_service_identity()` used a separate
`TokenUser` reader in `lib.rs` which did not validate the complete
kernel-issued SID pointer and structure inside the returned
`GetTokenInformation` buffer before invoking `EqualSid`.
The C4o SCM observer had already hardened that path in OC-04. Leaving two
independent implementations exposed ordinary probes to inconsistent bounds,
length accounting, and Win32 error handling.

## Targeted remediation

The Windows-only C4g wrapper now calls
`windows_token::verify_current_process_identity()`. It opens its
own **read-only TOKEN_QUERY handle**, resolves the fixed independently
provisioned `NT SERVICE\\JameDesktopCommanderAuthority` SID and
uses the same `token_user_matches_service` query and bounded SID decoder
as C4o. This helper validates the complete `TokenUser` response including
pointers and subauthority lengths before calling `EqualSid`.
Missing virtual account, mismatched identity, insufficient/truncated
Win32 buffers and failed native queries return `IdentityDenied` without
revealing credentials or attempting another authorization path.

Within the real SCM process, C4o still acquires **one process token handle**
and inspects its identity, type, groups, restricted SIDs, integrity and
privileges on that same handle before terminal `Stopped` status. A
standalone preflight invocation owns a **separate** handle because it is
a separate caller; no SCM second-handle preflight was reintroduced.

The Linux C4g code and its real/effective/saved UID/GID and supplementary
group checks are unchanged. Public MCP methods, native dependency versions,
tool names, SCM service installation and authorization state are unchanged.

## Test and release gates

- TDD RED: the missing shared preflight contract rejected the old
  duplicate Win32 implementation before refactoring.
- Native Windows local GREEN: pinned Rust 1.91.1 `cargo test --locked
  --offline`, Rustfmt, Clippy `-D warnings`, an ordinary-user
  independent-preflight denial test and malformed/out-of-range SID tests.
- Node static contract and existing SCM acceptance fixtures pass locally;
  mandatory Linux/Windows CI, CodeQL, governance and portable candidates
  are required before merger and protected postmerge validation.
- No call grants operations. No `Running` status, no bypass if a query
  fails and no relaxation of `releaseEligible: false`.

**Still open:** real least-privilege privilege/group allowlists,
independently trusted policy custody, authenticated IPC, revocation,
handle-bound production filesystem migration C5, adversarial D,
packaging/distribution E, and audited production deployment. An ordinary
preflight denial test is not positive evidence of a deployed service.
