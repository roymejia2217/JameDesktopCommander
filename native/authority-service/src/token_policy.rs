//! Pure, platform-independent classification for the non-release SCM token
//! audit. This module cannot authorize operations or confer OS privileges.
//!
//! Real token acquisition and attribute validation are separate milestones.

/// Categorically describes an in-process token observation; never grants I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenFinding {
    /// All *reviewed* observations match the deny-only synthetic policy.
    ObservedDenyOnly,
    /// A mandatory identity, group or token-mode boundary was violated.
    BoundaryViolation,
    /// Required evidence is absent or the privilege baseline is unapproved.
    Unverifiable,
}

/// Values must originate from validated, kernel-issued token structures.
/// This type by itself is NOT evidence that such validation took place.
#[derive(Debug, Clone, Copy)]
pub struct TokenEvidence<'a> {
    pub identity_matches: bool,
    pub is_primary: bool,
    pub restricted_service_sid_attributes: Option<u32>,
    pub elevated_group_enabled: bool,
    pub integrity_rid: Option<u32>,
    pub enabled_privileges: &'a [&'a str],
}

const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;

/// Classify a previously verified snapshot. In particular, privileges not
/// approved by actual SCM evidence MUST NOT receive a permissive default.
#[must_use]
pub fn classify_token(snapshot: &TokenEvidence<'_>) -> TokenFinding {
    if !snapshot.identity_matches || !snapshot.is_primary || snapshot.elevated_group_enabled {
        return TokenFinding::BoundaryViolation;
    }
    match snapshot.restricted_service_sid_attributes {
        Some(attrs) if attrs & SE_GROUP_ENABLED != 0 && attrs & SE_GROUP_USE_FOR_DENY_ONLY == 0 => {
        }
        _ => return TokenFinding::BoundaryViolation,
    }

    // Absent/malformed integrity observations are not a positive proof.
    if !matches!(snapshot.integrity_rid, Some(rid) if rid != 0) {
        return TokenFinding::Unverifiable;
    }
    if snapshot.enabled_privileges.iter().any(|name| {
        matches!(
            *name,
            "SeDebugPrivilege"
                | "SeTcbPrivilege"
                | "SeCreateTokenPrivilege"
                | "SeLoadDriverPrivilege"
        )
    }) {
        return TokenFinding::BoundaryViolation;
    }
    if !snapshot.enabled_privileges.is_empty() {
        return TokenFinding::Unverifiable;
    }
    TokenFinding::ObservedDenyOnly
}

/// Enforce a cap and checked byte arithmetic before interpreting an array
/// supplied by any variable-size token-information query.
///
/// `header_bytes` is the complete fixed header size, excluding elements.
/// Passing this check does NOT validate native pointers, alignment or SIDs.
#[must_use]
pub fn bounded_token_array(
    total_bytes: usize,
    header_bytes: usize,
    element_bytes: usize,
    count: usize,
) -> bool {
    const MAX_QUERY_BYTES: usize = 16_384;
    const MAX_ENTRIES: usize = 128;
    if total_bytes == 0
        || total_bytes > MAX_QUERY_BYTES
        || header_bytes == 0
        || count > MAX_ENTRIES
        || (count != 0 && element_bytes == 0)
    {
        return false;
    }
    count
        .checked_mul(element_bytes)
        .and_then(|entries| header_bytes.checked_add(entries))
        .is_some_and(|required| required <= total_bytes)
}
