//! Disposable SCM-child token observation; not an MCP client or grant.
//! The CI-only issuer must retain the child process handle.
#[cfg(windows)]
fn main() -> std::process::ExitCode {
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
