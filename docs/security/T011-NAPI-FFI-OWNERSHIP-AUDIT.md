# T011 / Security #124 — N-API native pointer ownership audit

**Scope:** Rust Code Scanning alert #12 (`rust/access-invalid-pointer`).
**Original baseline:** protected `main` at `d3c3aa3b2407d97ee8adf99878ed850005633c93`.
**Reverified:** protected `main` at `23016abb05b8613e4508f59928cdceb9124f755b`.
**Status:** investigative evidence, **not** an alert disposition, privilege
approval, production acceptance, or release authorization.

## Observed scanner evidence

The 2026-10-18 protected-main CodeQL Rust SARIF analysis ID
`1976105527` reports one result for `rust/access-invalid-pointer`,
at `native/capability-probe/src/lib.rs:33-34` (the `#[napi]`
`RootCapability` expansion). The flow repeats the same three steps
twice: a generated `std::ptr::null_mut()` value, assignment to
`wrapped_val`, and a subsequent `(...)` dereference. The SARIF
does **not** display the `napi_unwrap` output assignment, Node-API
return-status gate, tag validation, or native borrow registration.
The location points to the derive invocation, not an explicit
handwritten Rust dereference. Protected-main Rust CodeQL analysis
`1977948204` repeats one result at the same `lib.rs:34` on commit
`23016abb05b8613e4508f59928cdceb9124f755b`; alert #12
remains HIGH/OPEN despite successful workflow execution.

Source provenance is from the exact locked registry dependencies:
`napi=3.14.2`, `napi-derive=3.6.12`,
`napi-derive-backend=6.1.5`, `cap-std=4.0.3`,
with native `napi8` on Windows and Linux.

## Reconstructed production-reachable synchronous path
1. `napi-derive-backend/src/codegen/struct.rs:168-242` generates
   `FromNapiRef` and `FromNapiMutRef`. Each initializes a raw
   `wrapped_val` to null, checks the result of `napi_unwrap` using
   `check_status!(...)?`, validates its class type tag, and calls
   `register_native_borrow_with_value(...)?` **before** constructing
   the Rust shared or exclusive reference.
2. `napi/src/bindgen_runtime/native_borrow.rs:204-240` rejects
   `value.is_null()` and incompatible shared/exclusive borrows.
   Lines 282-350 require an active scope, propagate registration
   errors, and push the acquired guard only on successful registration.
   Thus a null result from a *successful* unwrap still cannot reach
   the generated dereference through this path.
3. `napi-derive-backend/src/codegen/fn.rs:305-325` installs
   `NativeBorrowScope` before argument/receiver conversion, calls
   `finish()` after conversion, and retains its guards during
   synchronous invocation **and** return conversion. A
   `NativeBorrowBarrier` prevents reentrant conversion from attaching
   new borrows to a suspended outer conversion scope.
4. For class method receivers, `fn.rs:407-439` obtains
   `this_ptr` via `CallbackInfo::unwrap_raw`, registers the
   corresponding borrow, then constructs a Rust reference.
   `napi/src/bindgen_runtime/callback_info.rs:304-334` checks
   `napi_unwrap` and, on native `napi8`, the type tag.
   The scope-registration null guard remains mandatory.
5. The only exposed `RootCapability` instance methods are
   synchronous; the `receiver-test-fixture` feature adds test-only
   shared/mutable-reference entry points. Async/factory/Wasm paths
   are **not** justified by this audit.
## Ownership and finalization chain

- `callback_info.rs:231-285` allocates a `Box<T>`, obtains a
  non-null pointer with `Box::into_raw`, and passes it to
  `napi_wrap` with `raw_finalize_unchecked::<T>` and a weak
  JavaScript object reference. On success, a matching reference-map
  entry is installed and the native `napi8` type tag is stamped.
- `bindgen_runtime/mod.rs:63-106` reconstructs the owned
  `Box<T>` in the finalizer, removes reference-map bookkeeping,
  executes user finalization, and releases the reference. This
  confirms intended single-owner disposal **on the normal path**,
  not a formal lifetime proof for arbitrary host teardown.
- The Node-API contract describes `napi_unwrap` as retrieving a
  native instance previously associated using `napi_wrap`.
  `napi_remove_wrap` detaches it and disables the former
  finalizer. Neither arbitrary detach nor native tag stamping is
  exposed through the current JavaScript `RootCapability` API.
- The tag is an identity check, **not** an unforgeable cryptographic
  capability. Another malicious in-process native addon or a
  compromised Node host is outside the unprivileged JavaScript
  boundary and is not proved safe by this analysis.
- No user-provided `RootCapability` method invokes
  `napi_remove_wrap`, manipulates a wrapped pointer, or has an
  asynchronous return holding `&RootCapability` beyond the callback.
  The default Node-API handle-scope guarantee establishes normal
  synchronous object reachability (see below). It does **not** prove
  arbitrary abnormal environment teardown or hostile native code.

Node-API reference: https://nodejs.org/api/n-api.html
(`napi_wrap`, `napi_unwrap`, `napi_remove_wrap`,
`napi_type_tag_object`, `napi_check_object_type_tag`).
## Synchronous Node-API handle-lifetime argument

Node-API's **Object lifetime management** contract states that
`napi_value` handles in the default scope keep objects live for the
entire native method call. A normal `napi_callback` already has a
default scope; explicit persistent references are needed when data
must outlive that call. References produced by `napi_wrap` with an
initial count of zero are weak, **not** permanent GC roots.

Source: https://nodejs.org/download/release/v26.8.2/docs/api/n-api.html
(Object lifetime management, `napi_get_cb_info`, `napi_wrap`).

1. `napi/src/bindgen_runtime/callback_info.rs:26-69` obtains
   `this` and argument `napi_value` handles via checked
   `napi_get_cb_info`; they belong to the native call's scope.
2. `callback_info.rs:78-118` wraps the constructor-owned
   `Box<RootCapability>` with `napi_wrap`, adopting finalizer
   ownership and recording a weak reference before type tagging.
3. `napi-derive-backend/src/codegen/struct.rs:168-242` checks
   `napi_unwrap` status and class type tag, then registers the
   checked, non-null borrow **before** constructing `&T`/`&mut T`.
4. `napi/src/bindgen_runtime/native_borrow.rs:119-184` creates
   the synchronous guard scope with `root_values=false`. The
   Node-API call's default handle scope, **not** the guard, keeps
   the JavaScript wrapper live. Guards enforce Rust aliasing.
5. `napi-derive-backend/src/codegen/fn.rs:305-325` keeps acquired
   guards alive through the synchronous call and return conversion.
   Its barrier prevents reentrant conversion into an outer scope.

Under the supported synchronous Node-API host contract, the
wrapped object cannot be finalized *because of ordinary GC* while
its native callback's handle scope is still live. This closes the
previously undocumented ordinary-GC reachability assumption,
**conditional on the Node-API implementation honoring its contract**.

## Scope, exceptions and independent-review requirements

- The contract above is **not** a guarantee for async/worker,
  Wasm/Emnapi, arbitrary foreign hosts or native teardown.
  Do not generalize it to the privileged SCM service.
- JavaScript callers cannot invoke `napi_remove_wrap` through
  `RootCapability`; a malicious addon in the same process could
  detach/reassign pointers and crosses the trusted-native boundary.
- Tag validation is class identity, not a cryptographic credential.
  The proof assumes a correctly tagged wrapper really owns the
  allocation provided to `napi_wrap`.
- A failed `napi_wrap` or type-tag operation, JS exception and
  `ObjectFinalize` error need independent examination of all
  cleanup paths. The normal-path finalizer uses
  `napi/src/bindgen_runtime/mod.rs:63-106`, but its mere presence
  does not prove teardown safety or single-free on every exit.
- PR #129's `global.gc()` calls occur while JavaScript retains
  the capability in its closure. This tests *reentrant aliasing*,
  **not** finalization of an unreferenced wrapped native object.
- Reviewer must independently reconcile current Rust SARIF
  `1977948204` (one result) with the generated borrow guard,
  reproduce the supported-platform native path and decide
  A (real defect), B (verified upstream fix) or C (analyzer limit).
  Do **not** dismiss #12 or mark #124 resolved from these notes.

## Independent adversarial evidence and remaining limits

Protected PRs #119-#125 tested cross-class receivers, prototype
spoofing, invalid native arguments, mutable/shared alias conflicts,
directory confinement, post-close behavior and bounded I/O.
PR #127 proved null-borrow rejection for shared and exclusive modes.
PR #129 covered synchronous JavaScript reentry, explicit GC calls,
nested alias conflicts and guard release after thrown exceptions.
Both passed protected Windows/Linux T011 and Node compatibility CI.
These checks establish observable invariants, not complete proof of
GC finalizer ordering or hostile native teardown. PR #128 resolved
CodeQL JavaScript HIGH alerts #3 and #4 automatically.

**Current assessment:** the SARIF null-initialization flow omits a
reachable pre-dereference null-rejection gate. It is a **plausible
interprocedural analyzer limitation**, not yet an independently
approved false-positive disposition. In particular, the source-level
checks do not establish the entire allocation lifetime if a
different native module detaches or rewraps the same JavaScript
object, if the host violates Node-API semantics, or during abnormal
environment teardown.

## Security decision gates

- **A / real flaw:** demonstrate a reachable failure and apply
  RED/GREEN native tests with minimal code or upstream fixes.
- **B / upstream fix:** require a documented exact upstream diff,
  compatible pinned versions and full locked CI validation.
- **C / analyzer limitation:** independent reviewer must confirm
  the provenance, constructor-wrap-finalizer lifetime, Node-API
  callback reachability, error exits and reentrancy assumptions
  against this specific SARIF trace. Only then consider a narrowly
  justified Code Scanning disposition; never bulk-dismiss alerts.
- Keep #12 **HIGH/OPEN** until one gate has review evidence.
  JS HIGH alerts #3/#4 are fixed as of PR #128; privileged SCM
  issue #80 stays open, T011 `releaseEligible:false` and deny-only.
- No protected policy custody, native token export, credentials,
  release artifacts, installed runtime or service configuration
  is changed by this document.
