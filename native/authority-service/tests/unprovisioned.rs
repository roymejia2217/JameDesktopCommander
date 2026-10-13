use jdc_authority_service::verify_service_identity;
use std::process::Command;

#[test]
fn ordinary_caller_cannot_spoof_service_identity_with_environment_or_flags() {
    let result = Command::new(env!("CARGO_BIN_EXE_jdc-authority-service"))
        .env("USERNAME", "JameDesktopCommanderAuthority")
        .env("USER", "jdc-authority")
        .env("JDC_AUTHORITY_IDENTITY", "jdc-authority")
        .arg("--allow-all")
        .output()
        .expect("probe process should launch");
    assert!(
        !result.status.success(),
        "no provisioned store or IPC may exist"
    );
    let stderr = String::from_utf8(result.stderr).expect("ASCII diagnostics");
    assert!(
        stderr.contains("E_IDENTITY_REQUIRED"),
        "normal host must not pass the OS identity gate: {stderr}"
    );
}

#[test]
fn ordinary_test_runner_is_not_the_protected_service_identity() {
    // This CI/normal-developer-host test MUST be run under a distinct user.
    // Cross-principal positive and negative ACL tests remain separate blockers.
    assert!(
        verify_service_identity().is_err(),
        "an ordinary CI account must not impersonate the dedicated service"
    );
}
