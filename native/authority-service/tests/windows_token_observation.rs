#[cfg(windows)]
#[test]
fn ordinary_windows_process_is_not_the_scm_virtual_account() {
    use jdc_authority_service::token_policy::TokenFinding;
    use jdc_authority_service::windows_token::observe_current_process_token;

    // This process is the unprivileged CI/test runner, never the SCM target.
    // Any missing/forged virtual-service identity must fail closed.
    assert_eq!(
        observe_current_process_token(),
        Ok(TokenFinding::BoundaryViolation)
    );
}
