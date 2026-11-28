//! Disposable SCM-child token observation; not an MCP client or grant.
//! The CI-only issuer must retain the child process handle.
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    if let Some(arg) = args.next() {
        if arg == "--fixed-resume-proof"
            && args.next().is_none()
            && jdc_authority_service::windows_token::verify_scm_fixture_identity(
                jdc_authority_service::windows_token::ScmFixtureRole::Issuer,
            )
            .is_ok()
        {
            return std::process::ExitCode::from(17);
        }
        return std::process::ExitCode::FAILURE;
    }
    if jdc_authority_service::verify_service_identity().is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("E_IDENTITY_REQUIRED");
        std::process::ExitCode::FAILURE
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
