use std::process::ExitCode;
fn main() -> ExitCode {
    if jdc_authority_service::verify_service_identity().is_err() {
        eprintln!("E_IDENTITY_REQUIRED");
        return ExitCode::FAILURE;
    }
    // Even a valid OS token cannot grant permission without an independently
    // protected durable state, authenticated IPC and pinned directory roots.
    // Explicitly deny ALL startup until those components are proven.
    eprintln!("E_POLICY_UNAVAILABLE");
    ExitCode::FAILURE
}
