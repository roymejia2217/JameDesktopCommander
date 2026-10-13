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
    /// Required token evidence is missing or invalid, never a CI acceptance.
    Unverifiable,
    /// Token evidence passed structural checks, but enabled privileges
    /// have not yet received an explicitly reviewed OS baseline.
    PrivilegeBaselineUnreviewed,
}

/// Terminal SCM denial reasons; no branch authorizes a running service.
/// Code 3 is reserved for verified-but-unreviewed privilege inventories.
#[must_use]
pub fn scm_terminal_denial_code(identity_valid: bool, observation: Option<TokenFinding>) -> u32 {
    if !identity_valid {
        return 2; // kernel-issued service identity required
    }
    match observation {
        Some(TokenFinding::ObservedDenyOnly) => 1, // policy unavailable
        Some(TokenFinding::PrivilegeBaselineUnreviewed) => 3, // privilege review missing
        Some(TokenFinding::BoundaryViolation) => 4, // token boundary violation
        Some(TokenFinding::Unverifiable) | None => 5, // invalid or missing evidence
    }
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
        return TokenFinding::PrivilegeBaselineUnreviewed;
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

/// Verify a native field spans only an aligned region within its query buffer.
/// No untrusted field pointer may be dereferenced before this returns true.
#[must_use]
pub fn bounded_buffer_span(
    buffer_addr: usize,
    total_len: usize,
    field_addr: usize,
    field_len: usize,
    alignment: usize,
) -> bool {
    if buffer_addr == 0
        || total_len == 0
        || field_len == 0
        || !alignment.is_power_of_two()
        || !field_addr.is_multiple_of(alignment)
    {
        return false;
    }
    let Some(buffer_end) = buffer_addr.checked_add(total_len) else {
        return false;
    };
    let Some(field_end) = field_addr.checked_add(field_len) else {
        return false;
    };
    field_addr >= buffer_addr && field_end <= buffer_end
}

/// Validate the fixed SID header and its subauthority byte count.
/// This is a structural validation only; identity equality is an OS check.
#[must_use]
pub fn bounded_sid_bytes(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 8 || bytes[0] != 1 {
        return None;
    }
    let count = usize::from(bytes[1]);
    if !(1..=15).contains(&count) {
        return None;
    }
    let len = count.checked_mul(4)?.checked_add(8)?;
    (len <= bytes.len()).then_some(len)
}
