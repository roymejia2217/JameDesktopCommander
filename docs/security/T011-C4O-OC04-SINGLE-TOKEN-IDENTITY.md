# T011-C4o OC-04 — Single-handle SCM identity attestation

**State:** Experimental, deny-only, non-release. This is not an authorized
broker, service installer or production filesystem safety claim.

## Problem fixed in the isolated Windows SCM candidate

The earlier C4g identity preflight called `OpenProcessToken` separately
from the C4o groups/privileges observer. The C4g `TokenUser` path also
relied on a kernel-supplied SID pointer without verifying its entire
location inside the returned query buffer. These gaps prevent a claim
that identity and privileges were checked against one token snapshot.

## New boundary

The real SCM dispatcher invokes only `observe_current_process_token()`.
The observer acquires one `TOKEN_QUERY` handle, and queries `TokenUser`
against that handle before requesting TokenType, TokenGroups,
TokenRestrictedSids, TokenIntegrityLevel and TokenPrivileges.

The expected service virtual-account SID remains independently
resolved from the constant `NT SERVICE\\JameDesktopCommanderAuthority`.
Any user SID pointer outside the bounded `GetTokenInformation` response,
a truncated SID header/subauthority array or failed lookup is
`TokenUnverifiable`. A structurally valid but mismatched user SID
produces `IdentityMismatch` and terminal SCM denial code 2.
The native handle is closed through RAII on every path.

Code 1 remains policy unavailable, 3 means an unapproved privilege
baseline, 4 means another mandatory token-boundary violation and 5 means
invalid/missing native evidence. No code grants I/O or `Running`.

The original public `verify_service_identity()` preflight remains for
standalone identity tests and non-SCM consumers; its deprecated Windows
SID buffer handling should be separately hardened or replaced before
claiming that API has equal safety. **SCM itself no longer uses it.**

## Verification and remaining work

TDD RED: new Rust `IdentityMismatch` variant was absent; Node contract
detected the two-token SCM path; Windows negative test required the new
result. Green must pass Rust tests, PowerShell AST, Rustfmt, Clippy
`-D warnings`, SCM Node tests and Windows/Linux native CI.

The ephemeral GitHub-hosted SCM fixture must still validate the exact
final denial and protected service DACL, nonadmin mutation denial and
unconditional cleanup. No local installed service may be touched.

This reduces token-handle inconsistency but does NOT establish an
approved whitelist for service privileges/groups or integrity, and
does not provide authenticated IPC, policy custody, revocation,
handle-bound production I/O, adversarial T011-D or distributable
T011-E. `releaseEligible: false` remains mandatory.
