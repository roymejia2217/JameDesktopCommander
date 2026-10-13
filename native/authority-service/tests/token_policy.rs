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
            TokenFinding::Unverifiable
        );
    }
    assert_eq!(
        classify_token(&minimal(&["SeDebugPrivilege"])),
        TokenFinding::BoundaryViolation,
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
