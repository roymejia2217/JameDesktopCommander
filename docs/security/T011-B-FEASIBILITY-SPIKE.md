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

**Reproducible dependency gate:** The first native feasibility run produced
identical Cargo.lock files on Windows 2025 and Ubuntu 24.04: 16,043 bytes,
SHA-256 a0d59a076a1184dab97b375c183b3b7af85cf5da7a6b3c13ed8ce34f26d1b4a8
(69 package records). This exact artifact is committed and MUST remain
unchanged during CI. Cargo metadata and builds run with --locked, without
generating the dependency graph. The maintained cargo-deny action is
commit-pinned and checks advisories, approved SPDX licenses and registry
provenance with no advisory exceptions. Any rejected or unidentified
dependency, license or security advisory blocks acceptance; a green status
must be verified in the native Windows/Linux matrix and independently
reconciled against the resulting original artifacts. Node 22.19 and Node 24
must both load and test the native binary on each operating system.
No runtime dependency is added to JDC's package-lock.json.

This spike is not part of the portable JDC bundle. Neither Rust nor an
on-host compiler is a deployment prerequisite. T011-C/D/E remain blocked
pending native security evidence, lifecycle design and full handler coverage.
No production services, installer, release or update are authorized.
