//! Disposable Linux child identity probe for systemd-origin CI acceptance.
//! A matching service UID/GID alone does NOT authenticate a desktop MCP client.
#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    if jdc_authority_service::verify_service_identity().is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("E_IDENTITY_REQUIRED");
        std::process::ExitCode::FAILURE
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
