# T011-B — Native filesystem capability feasibility

**Status:** Experimental DRAFT, not a production authorization fix.

This isolated native probe uses cap-std 4.0.3, napi 3.14.2 and pinned
Node-API/Rust build dependencies. The cap-std Windows device-name issue
GHSA-hxf5-99xg-86hw was fixed in 3.4.1, but JDC must still test the
affected path family and all Windows junction/case-sensitive scenarios.

The proof-of-concept has an intentionally ambient constructor solely for
disposable tests. It MUST NOT be exposed to MCP clients or imported by the JDC
server. File operations after construction are relative to an open directory
capability; explicit close invalidates it. The tests exercise reads, rewrite,
append, traversal, absolute paths, symlink/junction escape, root-name change,
and reserved Windows device names. A PASS cannot establish complete
concurrency safety or a hardened policy manager.

**Dependency acceptance is deliberately two-stage:** First CI compiles on
Windows 2025 and Ubuntu 24.04 using Rust 1.91.1, generating a temporary
Cargo.lock with exact direct dependency versions. CI tests Node 22.19 and
Node 24 and retains the unpublished lock and binary for one day. Do **not**
merge this PR with a generated-only lock. Audit dependencies/licenses,
commit the approved Cargo.lock, switch CI to build only with --locked,
repeat both platforms and perform independent artifact verification.
No runtime dependency is added to JDC's package-lock.json.

This spike is not part of the portable JDC bundle. Neither Rust nor an
on-host compiler is a deployment prerequisite. T011-C/D/E remain blocked
pending native security evidence, lifecycle design and full handler coverage.
No production services, installer, release or update are authorized.
