# T011 / Security #124 — N-API native pointer ownership audit

**Scope:** Rust Code Scanning alert #12 (`rust/access-invalid-pointer`).
**Baseline:** protected `main` at `d3c3aa3b2407d97ee8adf99878ed850005633c93`.
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
handwritten Rust dereference. A successful CodeQL job did **not**
clear the alert; the live latest instance remains HIGH/OPEN.

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
  Synchronous object reachability throughout the engine callback
  and abnormal environment teardown require external API guarantees;
  they are not established merely by successful behavioral tests.

Node-API reference: https://nodejs.org/api/n-api.html
(`napi_wrap`, `napi_unwrap`, `napi_remove_wrap`,
`napi_type_tag_object`, `napi_check_object_type_tag`).
## Independent adversarial evidence and remaining limits

Protected PRs #119-#125 tested cross-class receivers, prototype
spoofing, invalid native arguments, mutable/shared alias conflicts,
directory confinement, post-close behavior and bounded I/O.
PR #125 and protected-main postmerge ran native Node 22/24 on
Windows and Linux with CI/CodeQL in SUCCESS. Those results
demonstrate observable behavior, not proof of every unsafe pointer
contract, finalizer ordering or process teardown.

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
  Keep separate JS HIGH alerts #3/#4 and privileged SCM issue #80
  open, with T011 `releaseEligible:false` and deny-only.
- No protected policy custody, native token export, credentials,
  release artifacts, installed runtime or service configuration
  is changed by this document.
