//! T011 native capability probe. No filesystem authority is exported by a
//! default build until receiver lifetime and OS-backed custody are accepted.
//! The full research implementation is only built with an explicit CI feature.

#[cfg(feature = "receiver-test-fixture")]
pub mod research_impl;

// A loadable, typed fail-closed default helps packaging prove that the native
// artifact cannot accidentally expose an unreviewed RootCapability receiver.
#[cfg(not(feature = "receiver-test-fixture"))]
#[napi_derive::napi]
pub fn restricted_capability_unavailable() -> napi::Result<()> {
    Err(napi::Error::from_reason(
        "E_CAPABILITY_UNAVAILABLE: native filesystem authority is not approved",
    ))
}
