# T011 #124 — Exclude JDC N-API capability from portable distribution

**Decision:** research binary stays in the separate native feasibility workflow; the unpublished portable Node candidate does **not** carry `native/jdc-capability-probe.node`. **Non-release**; not a resolution of #124, nor an endorsement of a new broker.

## Basis

The protected-main `native/capability-probe/src/lib.rs` intentionally exports only `restrictedCapabilityUnavailable()`, which throws `E_CAPABILITY_UNAVAILABLE`. It contains no `RootCapability` class. The unsafe receiver/lifetime investigations and original adversarial tests remain in research PR #131. A passing native addon smoke test cannot prove FFI soundness, and the presence of a deny-only binary inside a candidate unnecessarily creates a native artifact that has no released filesystem operation to serve.

## Enforced candidate behavior

The Windows/Linux `distribution-candidate.yml` no longer compiles an experimental Rust addon that is categorically excluded from its payload. The existing independent `t011-capability-feasibility.yml` workflow still compiles the exact locked Rust native library, verifies deny-only exports on **both Node 22.19 and Node 24** and runs platform-native security tests. Both workflows continue to run on protected-`main` pushes and pull requests targeting `main`. The staging step remains opted OUT of the native addon. The executable `scripts/distribution-candidate.mjs` refuses `JDC_CANDIDATE_INCLUDE_NATIVE=1` before performing any operation, and no longer supplies `nativeAddon` to the candidate builder. The builder/validator checks native addons in isolated negative/inventory tests, but the governed CLI never includes that optional argument.

The candidate manifest must omit `nativeCapabilityAddon`, the candidate root must omit the `native/` directory, and the file inventory/TAR round-trip verifier rejects any newly introduced native path. The standard Node runtime, original MCP tool contracts, complete SHA-256 inventory, source-commit build attestation, symlink guard, detached TAR round-trip and external MCP smoke gates remain unchanged.

## Explicit limits / production gates

- This is a **distribution surface reduction**, not proof that the original N-API receiver implementation is safe. Do not re-enable a native capability class because the metadata/build gates pass.
- The N-API research crate and Rust dependency checks remain mandatory in the independent T011 feasibility workflow, not in the shipping payload's packaging job. The workflow is not bypassed, weakened or marked optional. Any future native interface requires an independent security-reviewed ownership contract, real cross-platform native acceptance and issue #124 disposition.
- The proposed OS-authenticated Rust IPC service (#139) is NOT live or integrated into production handlers. `native/authority-service/src/main.rs` remains fail-closed. Existing portable Node tools do not inherit a new native capability or extra privileges from this change.
- Issue #148 requires independently demonstrated cross-root hardlink object isolation. Experimental PR #175 is not a production fix.
- No main-branch commit, deployed plugin, Windows SCM, Linux systemd unit or npm public release is modified by this DRAFT change.

**Gate:** `releaseEligible:false` until #124, #139 and #148 have independent documented dispositions and the full repository CI + hosted Windows/Linux candidate round-trip tests pass at the exact merged commit.
