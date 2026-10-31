//! Disposable Linux systemd-activation probe for the issuer-owned read path.
//! It is never installed by packaging and does not change the deny-only service binary.
use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn run() -> Result<(), ()> {
    use jdc_authority_service::linux_issuer_bootstrap::UnissuedIssuer;
    use std::time::Duration;

    jdc_authority_service::verify_service_identity().map_err(|_| ())?;
    let mut issuer = UnissuedIssuer::observe_os_attested().map_err(|_| ())?;
    // Two independent authenticated sessions share the same OS-attested
    // issuer, retained root handles and durable replay ledger. The count is
    // fixed in this disposable probe, never client- or environment-controlled.
    for _ in 0..3 {
        issuer
            .dispatch_one_inherited_readonly_reply(Duration::from_secs(5))
            .map_err(|_| ())?;
    }
    println!("T011_ISSUER_READ_E2E_SERVICE_PASS_NONRELEASE");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), ()> {
    Err(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            eprintln!("E_ISSUER_READ_E2E_DENIED");
            ExitCode::FAILURE
        }
    }
}
