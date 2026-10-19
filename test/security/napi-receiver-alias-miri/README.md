# napi-receiver-alias-miri

**Issue:** #124 / CodeQL HIGH #12. **Status:** research, non-release.

This zero-dependency crate models the **specific** receiver expression emitted by
locked `napi-derive-backend 6.1.5` in `src/codegen/fn.rs:402–439`:
`Box::leak(Box::from_raw(this_ptr))`. It preserves a shared reference across
a second conversion of the same `RootCapability` allocation and reads the
outer reference afterwards. The first control creates shared Rust references
without reconstructing ownership while the callback is active. A second
control exercises the **same** `Box::leak(Box::from_raw(ptr))` conversion
in two *sequential, nonoverlapping* calls. Its official Miri outcome is
pending remote execution; ordinary Rust success is insufficient.

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


**Recorded experimental outcome**

PR #131, workflow run
[39243989005](https://github.com/roymejia2217/JameDesktopCommander/actions/runs/39243989005)
successfully installed the pinned official Miri toolchain. The direct
shared-pointer control **passed**, but the generated-expression model
**failed** with `Undefined Behavior`: a second `Box::from_raw`
performed a `Unique` retag and invalidated the earlier shared reference.
The error surfaced when the outer reference was read after reentry.
This is a reproducible model failure, **not** a missing Rust toolchain.

**Native reachability fixture**

Under `receiver-test-fixture` **only**, `RootCapability` also exposes
`probeReceiverAcrossJsCallback` through an entire feature-gated
`#[napi] impl` block. The Node subprocess in
`test/security/capability-reentrant-borrow-child.cjs` invokes that
method recursively, retains the outer `&self` across the inner call,
runs explicit GC, denies an overlapping mutable argument borrow, and
checks guard release after normal and exceptional returns.
The default-feature artifact must **not** expose this method.

This confirms that the generated `&self` receiver can be exercised
with nested JavaScript callbacks in a test fixture; Node success is
**not** a soundness proof and does not erase the independent Miri
diagnostic. Production `RootCapability` methods do not themselves
accept JavaScript callbacks; reachability in the shipped public API,
actual unsafe-Rust aliasing under Node-API FFI, and a compatible
upstream correction all remain security review gates. Leave PR #131
in draft, issue #124 and CodeQL #12 open, and T011 non-release.


## Install

No installation is required for the production app. This test-only
crate has zero dependencies. The CI job provisions the pinned official
Miri toolchain on a disposable GitHub-hosted Linux runner.

## Usage

Run ordinary checks with
`cargo +1.91.1 test --locked --manifest-path test/security/napi-receiver-alias-miri/Cargo.toml`.
The dedicated GitHub Actions workflow runs the Miri interpreter and
is intentionally **RED** while the ownership diagnostic remains.

## Contributing

Discuss proposed proof improvements under issue #124. Preserve the
original failed Miri case and a passing control; do not replace an
unsafe model with a different model merely to obtain a green check.
Any upstream or local fix requires separate architectural review.

## License

See the parent repository's `LICENSE` file.
