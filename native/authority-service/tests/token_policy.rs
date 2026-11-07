use jdc_authority_service::token_policy::{
    bounded_token_array, classify_token, TokenEvidence, TokenFinding,
};

fn minimal<'a>(enabled_privileges: &'a [&'a str]) -> TokenEvidence<'a> {
    TokenEvidence {
        identity_matches: true,
        is_primary: true,
        restricted_service_sid_attributes: Some(0x4),
        elevated_group_enabled: false,
        integrity_rid: Some(0x2000),
        enabled_privileges,
    }
}

#[test]
fn genuine_restricted_primary_without_enabled_privileges_is_observable() {
    assert_eq!(
        classify_token(&minimal(&[])),
        TokenFinding::ObservedDenyOnly
    );
}

#[test]
fn identity_restricted_sid_and_group_failures_are_denied() {
    let mut snapshot = minimal(&[]);
    snapshot.identity_matches = false;
    assert_eq!(classify_token(&snapshot), TokenFinding::BoundaryViolation);

    snapshot = minimal(&[]);
    snapshot.is_primary = false;
    assert_eq!(classify_token(&snapshot), TokenFinding::BoundaryViolation);
    snapshot = minimal(&[]);
    snapshot.restricted_service_sid_attributes = None;
    assert_eq!(classify_token(&snapshot), TokenFinding::BoundaryViolation);
    snapshot = minimal(&[]);
    snapshot.restricted_service_sid_attributes = Some(0x10);
    assert_eq!(classify_token(&snapshot), TokenFinding::BoundaryViolation);
    snapshot = minimal(&[]);
    snapshot.elevated_group_enabled = true;
    assert_eq!(classify_token(&snapshot), TokenFinding::BoundaryViolation);
}

#[test]
fn privilege_inventory_is_not_preapproved_without_real_scm_baseline() {
    for name in [
        "SeChangeNotifyPrivilege",
        "SeImpersonatePrivilege",
        "UnknownPrivilege",
    ] {
        assert_eq!(
            classify_token(&minimal(&[name])),
            TokenFinding::PrivilegeBaselineUnreviewed
        );
    }
    assert_eq!(
        classify_token(&minimal(&["SeDebugPrivilege"])),
        TokenFinding::BoundaryViolation,
    );
}

#[test]
fn security_sensitive_privilege_names_are_case_insensitive_without_prefix_matching() {
    use jdc_authority_service::token_policy::scm_terminal_denial_code;

    for name in [
        "SeDebugPrivilege",
        "sedebugprivilege",
        "SEDEBUGPRIVILEGE",
        "sEtCbPrIvIlEgE",
        "secreatetokenprivilege",
        "SELOADDRIVERPRIVILEGE",
    ] {
        let finding = classify_token(&minimal(&[name]));
        assert_eq!(
            finding,
            TokenFinding::BoundaryViolation,
            "sensitive privilege {name} must be a policy boundary violation",
        );
        assert_eq!(
            scm_terminal_denial_code(Some(finding)),
            4,
            "critical privilege evidence must produce boundary-violation SCM code",
        );
    }
    for name in [
        "SeDebugPrivilegeExtra",
        "NotSeDebugPrivilege",
        "SeDebugPrivilege ",
        "SeDebugPrivilegeé",
        "SeChangeNotifyPrivilege",
    ] {
        assert_eq!(
            classify_token(&minimal(&[name])),
            TokenFinding::PrivilegeBaselineUnreviewed,
            "no substring, whitespace, or Unicode normalization may authorize or reclassify",
        );
    }
}

#[test]
fn native_integrity_sid_requires_exact_single_rid_structure() {
    use jdc_authority_service::token_policy::integrity_sid_rid;
    // Windows mandatory-integrity authority S-1-16, one subauthority.
    let medium = [1u8, 1, 0, 0, 0, 0, 0, 16, 0, 32, 0, 0];
    assert_eq!(integrity_sid_rid(&medium), Some(0x2000));
    assert_eq!(integrity_sid_rid(&medium[..11]), None);

    let mut forged = medium;
    forged[1] = 0;
    assert_eq!(integrity_sid_rid(&forged), None);
    forged = medium;
    forged[0] = 2;
    assert_eq!(integrity_sid_rid(&forged), None);
    forged = medium;
    forged[7] = 5;
    assert_eq!(integrity_sid_rid(&forged), None);
    forged = medium;
    forged[8..12].fill(0);
    assert_eq!(integrity_sid_rid(&forged), None);

    // Two subauthorities under S-1-16 must not be interpreted as an RID
    // taken from the final four bytes.
    let extra = [1u8, 2, 0, 0, 0, 0, 0, 16, 0, 32, 0, 0, 0, 48, 0, 0];
    assert_eq!(integrity_sid_rid(&extra), None);
    assert_eq!(integrity_sid_rid(&extra[..12]), None);
}

#[test]
fn privilege_luid_inventory_rejects_ambiguous_or_unsupported_records() {
    use jdc_authority_service::token_policy::{
        validated_enabled_privilege_indices, PrivilegeRecord,
    };
    let disabled = PrivilegeRecord {
        luid_low: 7,
        luid_high: -1,
        attributes: 0,
    };
    let enabled = PrivilegeRecord {
        luid_low: 8,
        luid_high: 0,
        attributes: 0x2,
    };
    let used = PrivilegeRecord {
        luid_low: 9,
        luid_high: 0,
        attributes: 0x8000_0002,
    };
    assert_eq!(validated_enabled_privilege_indices(&[]), Some(vec![]));
    assert_eq!(
        validated_enabled_privilege_indices(&[disabled, enabled, used]),
        Some(vec![1, 2])
    );
    // Duplicate LUID even with different enabled bits is ambiguous.
    let duplicate = PrivilegeRecord {
        attributes: 0x2,
        ..disabled
    };
    assert_eq!(
        validated_enabled_privilege_indices(&[disabled, duplicate]),
        None
    );
    // Different HighPart is a distinct LUID: never compare only LowPart.
    let different_high = PrivilegeRecord {
        luid_high: 0,
        ..disabled
    };
    assert_eq!(
        validated_enabled_privilege_indices(&[disabled, different_high]),
        Some(vec![])
    );
    for forbidden in [0x4, 0x8, 0x10, 0x4000_0000, u32::MAX] {
        assert_eq!(
            validated_enabled_privilege_indices(&[PrivilegeRecord {
                attributes: forbidden,
                ..enabled
            }]),
            None,
            "unsupported TokenPrivileges attribute: {forbidden:#x}"
        );
    }
    // ENABLED_BY_DEFAULT and USED_FOR_ACCESS are documented bits,
    // but neither alone implies an enabled privilege.
    assert_eq!(
        validated_enabled_privilege_indices(&[
            PrivilegeRecord {
                attributes: 0x1,
                ..disabled
            },
            PrivilegeRecord {
                attributes: 0x8000_0000,
                ..enabled
            }
        ]),
        Some(vec![])
    );
}

#[test]
fn absent_or_invalid_integrity_is_not_observed_as_success() {
    let mut snapshot = minimal(&[]);
    snapshot.integrity_rid = None;
    assert_eq!(classify_token(&snapshot), TokenFinding::Unverifiable);
    snapshot.integrity_rid = Some(0);
    assert_eq!(classify_token(&snapshot), TokenFinding::Unverifiable);
}

#[test]
fn variable_arrays_reject_truncation_and_oversized_counts() {
    assert!(bounded_token_array(32, 8, 8, 3));
    assert!(bounded_token_array(8, 8, 8, 0));
    assert!(!bounded_token_array(31, 8, 8, 3));
    assert!(!bounded_token_array(7, 8, 8, 0));
    assert!(!bounded_token_array(16_385, 8, 8, 1));
    assert!(!bounded_token_array(16, 8, 8, 129));
    assert!(!bounded_token_array(16, 8, 0, 1));
    assert!(!bounded_token_array(16, usize::MAX, 8, 1));
}

#[test]
fn raw_windows_token_pointer_ranges_fail_closed() {
    use jdc_authority_service::token_policy::bounded_buffer_span;
    assert!(bounded_buffer_span(0x1000, 96, 0x1010, 16, 8));
    assert!(!bounded_buffer_span(0x1000, 96, 0x0fff, 8, 8));
    assert!(!bounded_buffer_span(0x1000, 96, 0x105f, 2, 1));
    assert!(!bounded_buffer_span(0x1000, 96, 0x1001, 8, 8));
    assert!(!bounded_buffer_span(0x1000, 96, 0x1010, 0, 8));
    assert!(!bounded_buffer_span(usize::MAX - 2, 8, usize::MAX, 4, 1));
    assert!(!bounded_buffer_span(0x1000, 96, 0x1010, 16, 3));
}

#[test]
fn windows_sid_size_is_revision_and_count_bounded() {
    use jdc_authority_service::token_policy::bounded_sid_bytes;
    // Revision 1, authority NT=5, one subauthority of RID 80.
    let sid = [1, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0];
    assert_eq!(bounded_sid_bytes(&sid), Some(12));
    assert_eq!(bounded_sid_bytes(&sid[..11]), None);
    assert_eq!(
        bounded_sid_bytes(&[2, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0]),
        None
    );
    assert_eq!(
        bounded_sid_bytes(&[1, 16, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0]),
        None
    );
    assert_eq!(bounded_sid_bytes(&[]), None);
}

#[test]
fn scm_terminal_reasons_are_distinct_and_permanently_deny_only() {
    use jdc_authority_service::token_policy::scm_terminal_denial_code;
    assert_eq!(scm_terminal_denial_code(None), 5);
    assert_eq!(
        scm_terminal_denial_code(Some(TokenFinding::IdentityMismatch)),
        2
    );
    assert_eq!(
        scm_terminal_denial_code(Some(TokenFinding::BoundaryViolation)),
        4
    );
    assert_eq!(
        scm_terminal_denial_code(Some(TokenFinding::Unverifiable)),
        5
    );
    assert_eq!(
        scm_terminal_denial_code(Some(TokenFinding::PrivilegeBaselineUnreviewed)),
        3
    );
    assert_eq!(
        scm_terminal_denial_code(Some(TokenFinding::ObservedDenyOnly)),
        1
    );
}
