use std::process::ExitCode;
fn main() -> ExitCode {
    if jdc_authority_service::verify_service_identity().is_err() {
        eprintln!("E_IDENTITY_REQUIRED");
        return ExitCode::FAILURE;
    }
    // Linux bootstrap observes the independently root-owned policy, opened
    // native roots and service-private replay-file identity. It NEVER opens
    // a SQLite VFS or issues a grant; missing/corrupt state always denies.
    #[cfg(target_os = "linux")]
    if jdc_authority_service::linux_issuer_bootstrap::UnissuedIssuer::observe_os_attested().is_err()
    {
        eprintln!("E_POLICY_UNAVAILABLE");
        return ExitCode::FAILURE;
    }
    // Even a valid OS token cannot grant permission without an independently
    // protected durable state, authenticated IPC and pinned directory roots.
    // Explicitly deny ALL startup until those components are proven.
    eprintln!("E_POLICY_UNAVAILABLE");
    ExitCode::FAILURE
}
