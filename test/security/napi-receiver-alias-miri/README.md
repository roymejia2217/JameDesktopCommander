# N-API receiver aliasing — isolated Miri experiment

**Issue:** #124 / CodeQL HIGH #12. **Status:** research, non-release.

This zero-dependency crate models the **specific** receiver expression emitted by
locked `napi-derive-backend 6.1.5` in `src/codegen/fn.rs:402–439`:
`Box::leak(Box::from_raw(this_ptr))`. It preserves a shared reference across
a second conversion of the same `RootCapability` allocation and reads the
outer reference afterwards. The control creates shared Rust references without
reconstructing ownership while the callback is active.

The current upstream `napi-rs/napi-rs` generator still contains the same
conversion in `crates/backend/src/codegen/fn.rs` (file blob
`3f1229e089d471ff05840af9074450c3165c90d8`, inspected 2026-10-19).

The official Miri interpreter runs on an ephemeral Ubuntu 24.04 runner with
pinned Rust `nightly-2026-06-29`; it is **not** installed on the user's Windows
machine. The workflow intentionally does **not** suppress Miri failures.
Ordinary stable Rust tests and Clippy are separate, insufficient controls.

**Interpretation:** even a Miri aliasing diagnostic only establishes a violation
in this *model*, not automatically in the entire `napi_wrap`/FFI callback
execution. Review the actual macro expansion, guard lifetime, source pointer
provenance, and Node-API ownership boundaries independently. If Miri passes,
it likewise cannot prove that production has no undefined behavior.

Do not suppress CodeQL #12, relax CI, activate privileged SCM, or publish
a release based on this experiment. Any supported upstream fix needs pinned
source review and full Windows/Linux native validation.
