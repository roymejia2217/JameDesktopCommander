//! Standalone, no-FFI research model for issue #124.
//! It mirrors the pinned napi-derive-backend 6.1.5 receiver conversion.
//! A result here alone does NOT establish that the full Node-API path is safe or unsafe.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
use std::{cell::Cell, sync::Mutex};

#[cfg(test)]
struct RootCapability {
    root: Mutex<Option<u32>>,
}

// Pinned upstream codegen/fn.rs:402-439 generates the same raw Box round-trip
// for a shared receiver after successful unwrap and borrow guard registration.
// SAFETY: For this deliberately unsafe model, the pointer comes from Box::into_raw
// and remains allocated until the test completes. Rust aliasing is under test.
#[cfg(test)]
unsafe fn generated_shared_receiver(ptr: *mut RootCapability) -> &'static RootCapability {
    let this: &RootCapability = Box::leak(unsafe { Box::from_raw(ptr) });
    this
}

// Research-only candidate for the upstream generated shared receiver.
// SAFETY: The owner remains alive and a native alias guard must exclude
// mutable/exclusive borrows during the entire returned reference lifetime.
// This model cannot itself prove those external Node-API invariants.
#[cfg(test)]
unsafe fn candidate_shared_receiver(ptr: *mut RootCapability) -> &'static RootCapability {
    unsafe { &*ptr }
}

// Research-only mutable candidate. In production this would require a
// live exclusive native guard and no reentrant shared or exclusive borrow.
#[cfg(test)]
unsafe fn candidate_exclusive_receiver(ptr: *mut RootCapability) -> &'static mut RootCapability {
    unsafe { &mut *ptr }
}

#[test]
fn candidate_nested_shared_receivers_with_live_outer() {
    let ptr = Box::into_raw(Box::new(RootCapability {
        root: Mutex::new(Some(7)),
    }));
    // SAFETY: This test keeps one Box owner, shares only through &T, and
    // avoids any exclusive borrow until both shared references are dead.
    unsafe {
        let outer = candidate_shared_receiver(ptr);
        let nested = candidate_shared_receiver(ptr);
        assert_eq!(*nested.root.lock().unwrap(), Some(7));
        assert_eq!(*outer.root.lock().unwrap(), Some(7));
        drop(Box::from_raw(ptr));
    }
}

#[test]
fn candidate_exclusive_receiver_without_overlap() {
    let ptr = Box::into_raw(Box::new(RootCapability {
        root: Mutex::new(Some(7)),
    }));
    // SAFETY: This exclusive reference is the only active reference to
    // the native allocation until it has finished being used.
    unsafe {
        let unique = candidate_exclusive_receiver(ptr);
        *unique.root.get_mut().unwrap() = Some(8);
        assert_eq!(*unique.root.get_mut().unwrap(), Some(8));
        drop(Box::from_raw(ptr));
    }
}

#[test]
fn control_plain_raw_shared_reentry() {
    let ptr = Box::into_raw(Box::new(RootCapability {
        root: Mutex::new(Some(7)),
    }));
    // SAFETY: both shared borrows end before a single final Box reconstruction.
    unsafe {
        let outer = &*ptr;
        let nested = &*ptr;
        assert_eq!(*nested.root.lock().unwrap(), Some(7));
        assert_eq!(*outer.root.lock().unwrap(), Some(7));
        drop(Box::from_raw(ptr));
    }
}

#[test]
fn control_sequential_generated_shared_receivers() {
    let ptr = Box::into_raw(Box::new(RootCapability {
        root: Mutex::new(Some(7)),
    }));
    // Each native-call-style shared receiver is used and becomes dead
    // before the next invocation reconstructs its Box from the raw pointer.
    // This distinguishes sequential dispatch from overlapping reentry.
    unsafe {
        {
            let first = generated_shared_receiver(ptr);
            assert_eq!(*first.root.lock().unwrap(), Some(7));
        }
        {
            let second = generated_shared_receiver(ptr);
            assert_eq!(*second.root.lock().unwrap(), Some(7));
        }
        drop(Box::from_raw(ptr));
    }
}

// Discriminating return-conversion model for the production list_directory path:
// the generated receiver is read by the Rust method BEFORE JavaScript array
// creation begins. NativeBorrowScope's alias guard outlives this Rust read,
// but the guard is not itself a Rust reference to RootCapability.
// This control must run under Miri, not merely standard cargo test.
#[test]
fn control_return_conversion_reentry_after_last_receiver_use() {
    let ptr = Box::into_raw(Box::new(RootCapability {
        root: Mutex::new(Some(7)),
    }));
    unsafe {
        let outer = generated_shared_receiver(ptr);
        let owned_result = *outer.root.lock().unwrap();
        // JavaScript property setter reenters after native return is owned.
        // Intentionally DO NOT read outer again after the nested conversion.
        let nested = generated_shared_receiver(ptr);
        assert_eq!(*nested.root.lock().unwrap(), Some(7));
        assert_eq!(owned_result, Some(7));
        drop(Box::from_raw(ptr));
    }
}

// This is an admission-count *model* of the pinned native shared borrow
// registry, not an implementation or proof of its full Node-API lifetime.
// It allows two simultaneous shared entries and tracks deterministic release.
#[cfg(test)]
struct ModelSharedGuard<'a> {
    shared: &'a Cell<usize>,
}

#[cfg(test)]
impl Drop for ModelSharedGuard<'_> {
    fn drop(&mut self) {
        let current = self.shared.get();
        assert!(current > 0, "model guard released without acquisition");
        self.shared.set(current - 1);
    }
}

#[cfg(test)]
fn acquire_model_shared(shared: &Cell<usize>) -> ModelSharedGuard<'_> {
    shared.set(shared.get() + 1);
    ModelSharedGuard { shared }
}

// Positive control: shared borrow admission does not itself invalidate two
// ordinary raw-pointer-derived &T references. One Box retains ownership.
#[test]
fn control_shared_guards_with_plain_raw_reentry() {
    let ptr = Box::into_raw(Box::new(RootCapability {
        root: Mutex::new(Some(7)),
    }));
    let shared = Cell::new(0);
    unsafe {
        let outer_guard = acquire_model_shared(&shared);
        let outer = &*ptr;
        let nested_guard = acquire_model_shared(&shared);
        let nested = &*ptr;
        assert_eq!(shared.get(), 2, "both shared entries must be admitted");
        assert_eq!(*nested.root.lock().unwrap(), Some(7));
        assert_eq!(*outer.root.lock().unwrap(), Some(7));
        drop(nested_guard);
        drop(outer_guard);
        assert_eq!(shared.get(), 0, "all model guards must release");
        drop(Box::from_raw(ptr));
    }
}

// Negative experimental model: the very same legal shared/shared admissions
// DO NOT prove that reconstructing Box ownership twice is sound. Keep this
// under official Miri (both borrow models) without expected-failure masking.
// A UB result means the source-expression model violates Miri, NOT that a
// shipping Node-API call has independently reproduced that exact violation.
#[test]
fn model_shared_guards_with_pinned_generated_reentry() {
    let ptr = Box::into_raw(Box::new(RootCapability {
        root: Mutex::new(Some(7)),
    }));
    let shared = Cell::new(0);
    unsafe {
        let outer_guard = acquire_model_shared(&shared);
        let outer = generated_shared_receiver(ptr);
        let nested_guard = acquire_model_shared(&shared);
        let nested = generated_shared_receiver(ptr);
        assert_eq!(shared.get(), 2, "the model must admit nested shared use");
        assert_eq!(*nested.root.lock().unwrap(), Some(7));
        assert_eq!(*outer.root.lock().unwrap(), Some(7));
        drop(nested_guard);
        drop(outer_guard);
        assert_eq!(shared.get(), 0);
        drop(Box::from_raw(ptr));
    }
}

// A return value can borrow bytes inline in its receiver. Unlike a
// Vec<String> owned return, these byte slices still point into the same
// allocation while N-API converts the return into a JavaScript array.
// This is a separate hypothetical upstream API shape, NOT a shipping
// RootCapability method and not an FFI lifetime proof.
#[cfg(test)]
struct InlineBorrowedReturn {
    inline: [u8; 4],
}

#[cfg(test)]
unsafe fn generated_inline_receiver(
    ptr: *mut InlineBorrowedReturn,
) -> &'static InlineBorrowedReturn {
    let this: &InlineBorrowedReturn = Box::leak(unsafe { Box::from_raw(ptr) });
    this
}

#[test]
fn control_inline_borrowed_return_with_nested_plain_shared_receiver() {
    let ptr = Box::into_raw(Box::new(InlineBorrowedReturn { inline: *b"ABCD" }));
    unsafe {
        let outer = &*ptr;
        let converted_later: &[u8] = &outer.inline;
        let nested = &*ptr;
        assert_eq!(nested.inline[0], b'A');
        assert_eq!(converted_later, b"ABCD");
        drop(Box::from_raw(ptr));
    }
}

#[test]
fn model_inline_borrowed_return_with_nested_generated_receiver() {
    let ptr = Box::into_raw(Box::new(InlineBorrowedReturn { inline: *b"ABCD" }));
    unsafe {
        let outer = generated_inline_receiver(ptr);
        let converted_later: &[u8] = &outer.inline;
        // The inner conversion recreates a unique Box while the return
        // still contains references into the previous receiver allocation.
        let nested = generated_inline_receiver(ptr);
        assert_eq!(nested.inline[0], b'A');
        assert_eq!(converted_later, b"ABCD");
        drop(Box::from_raw(ptr));
    }
}

#[test]
fn model_pinned_generated_shared_reentry() {
    let ptr = Box::into_raw(Box::new(RootCapability {
        root: Mutex::new(Some(7)),
    }));
    // SAFETY: Only allocation validity is assumed here; the experiment asks
    // Miri to assess whether repeated Box::from_raw/leak preserves Rust aliasing
    // while the first shared reference remains live across a nested conversion.
    unsafe {
        let outer = generated_shared_receiver(ptr);
        let nested = generated_shared_receiver(ptr);
        assert_eq!(*nested.root.lock().unwrap(), Some(7));
        assert_eq!(*outer.root.lock().unwrap(), Some(7));
        // Mirrors Node-API finalizer ownership after callback references end.
        drop(Box::from_raw(ptr));
    }
}
