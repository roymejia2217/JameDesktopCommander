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
