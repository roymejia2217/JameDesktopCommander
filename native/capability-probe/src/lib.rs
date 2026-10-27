//! Non-authorizing, deny-only native addon for candidate packaging.
//! Unsafe native class research is retained only on the separate #131
//! investigation branch and is not built or shipped from this crate.
//! Filesystem operations require an independently reviewed broker (#139).

#[napi_derive::napi]
pub fn restricted_capability_unavailable() -> napi::Result<()> {
    Err(napi::Error::from_reason(
        "E_CAPABILITY_UNAVAILABLE: native filesystem authority is not approved",
    ))
}
