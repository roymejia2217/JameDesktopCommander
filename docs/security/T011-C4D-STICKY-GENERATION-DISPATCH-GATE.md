# T011-C4d: generation pre-replay dispatch fencing (NON-RELEASE)

**Issue:** #139. This is a fail-closed dispatch-ordering regression guard, not a production grant issuer or a replay service. Neither the installed Windows server nor the Linux systemd service is modified.

## Contract

`SealedDirectoryGrant` now requires two independent private admissions before calling any rooted filesystem operation:

1. A generation admission, checked after canonical frame, exact rootRef and exact pinned epoch validation.
2. A one-shot replay claim for the already validated canonical UUIDv4, performed only after successful generation admission and before I/O.

The production-compiled `GenerationAdmission` currently has **only an unavailable/default denial**. It does not accept a client pathname, epoch, hash, policy or principal, and cannot be built by downstream callers as a grant. The separately implemented Linux `PolicyEpochMonitor` genuinely observes root-owned policy and witness changes, but **has NOT yet been bound to a trusted persistent grant owner**. Treat this ordering as a prerequisite and never advertise live revocation.

The existing synthetic test fixture gains a strictly test-only `GenerationAdmission::SyntheticTestOnly`: it pins epoch 7 and permanently poisons itself upon any mismatched observation, even if epoch 7 subsequently returns. An unavailable or poisoned generation denies **before** synthetic replay accounting and **before** file creation. The main Linux/Windows service binaries remain `E_POLICY_UNAVAILABLE`, with no public positive issuer. A future issuer must prove an OS-attested generation, durable OS-protected replay claim and serialization/cancellation across all in-flight filesystem operations. Without that, the new code does not establish linearizable revocation or rollback resistance across a reboot.

## TDD and verification

A native Rust unit test first produced RED E0609 for missing generation field. The new test asserts unavailable generation denial without a replay claim, denial after a synthetic forward epoch transition, and irreversible denial after restoring the old epoch. Existing positive, duplicate-ID, invalid-root, failed-I/O and separate-kernel-peer tests remain unchanged; no skip, xfail or weakened assertion. Version-pinned Rust 1.91.1 Windows library, target, doc tests, Clippy `-D warnings`, fmt and diff checks are mandatory. Linux-specific compilation and real cross-OS native regression remain dependent on exact-HEAD CI.

**Release disposition:** `releaseEligible:false`; #139, #124 and #148 remain P0 OPEN. No claim that a successfully passing CI independently authenticates policy provenance, protected replay, all-handler migration or cross-root inode isolation.
