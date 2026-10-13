# T011-C4o / OC-03.2 — Windows token observation primitives

**Status:** Unreleased, deny-only, partial implementation. No SCM acceptance
claimed. Base protected commit: `35778de6881d15b9076b384432702ad1ff28f098`.

## Change boundary

The Windows-only `windows_token` library module uses documented Microsoft
process-token APIs via the existing pinned `windows-sys 0.61.2` dependency:

- `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY)` and RAII `CloseHandle`
- `GetTokenInformation` for `TokenType`, `TokenGroups`,
  `TokenRestrictedSids`, `TokenPrivileges` and `TokenIntegrityLevel`
- Existing C4g `TokenUser` proof through `verify_service_identity()`
- Independently provisioned service SID via `LookupAccountNameW`
- `IsWellKnownSid`, `EqualSid` and `LookupPrivilegeNameW`

All returned data stays inside the process; no raw SID, access token,
privilege inventory, secret or caller-controlled evidence is logged.

## Buffer and failure rules

Use bounded Win32 two-call queries with the actual
`ERROR_INSUFFICIENT_BUFFER` precondition, a 16 KiB maximum, aligned
storage, checked returned lengths and deterministic resource cleanup.
Before dereferencing a variable SID pointer, establish that both the SID
header and complete subauthority bytes lie inside its originating query
buffer. Cap token group and privilege arrays at 128 elements and reject
overflow, truncated structures, invalid SID revisions, unexpected
duplicate target SIDs and failed privilege-name lookups.

Unknown privilege names, unresolved account SIDs and unreadable token
structures do not produce a positive classification. No permissive
fallback is introduced. This is a read-only proof surface.

## TDD / completed local evidence

- RED: Rust E0432 for missing `bounded_buffer_span` and
  `bounded_sid_bytes` functions.
- RED: Rust E0432 for unavailable `windows_token` module.
- GREEN: Native Windows tests for pointer bounds, SID validation,
  invalid query handles and ordinary non-SCM token rejection.
- Existing identity-denial tests, crate tests, Clippy with
  `-D warnings` and Rustfmt must remain green.

## Explicitly unproven

The observation function is **not invoked by the SCM service entry
point**. Existing `windows_scm.rs` must continue reporting only its
previous deny-only identity / policy outcomes. This slice cannot prove
the restricted SID attributes or privilege inventory of a real SCM
service process. No SCM status code is reinterpreted as an audit pass.

Current `TokenEvidence` classification is provisional: actual Windows
group/privilege baselines have not been independently reviewed and the
token is not an authorization source. The C4g identity preflight and
the observer currently acquire separate handles to the same process
token; consolidation into one token handle remains a review item.
Elevated principals, inherited handles, arbitrary enabled groups,
DLL search paths, authentic IPC, custody, rollback and handle-bound
file I/O remain outside this slice.

## Next governed gates

1. Review real Windows runner token evidence without publishing raw
   privilege inventories or adding hidden test overrides.
2. Review approved identity/group/privilege policy against those facts
   and the attack model; add explicit negative controls.
3. Wire the audit **inside** the actual SCM dispatcher before
   terminal `Stopped` and give audit rejection a distinct SCM reason.
4. Execute disposable-runner real-SCM acceptance and enforce the
   denial status, DACL and complete cleanup in the existing required
   Native probe (win32-x64) job.
5. Require all PR and postmerge checks. Keep `releaseEligible: false`.

Windows installed JDC runtime, tunnel and services remain unchanged.
