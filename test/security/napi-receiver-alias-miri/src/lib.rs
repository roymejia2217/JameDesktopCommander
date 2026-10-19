//! Standalone, no-FFI research model for issue #124.
//! It mirrors the pinned napi-derive-backend 6.1.5 receiver conversion.
//! A result here alone does NOT establish that the full Node-API path is safe or unsafe.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
use std::sync::Mutex;

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
