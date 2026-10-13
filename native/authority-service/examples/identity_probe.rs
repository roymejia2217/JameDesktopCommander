//! CI-only positive/negative service-identity probe, not a service entrypoint.
use std::process::ExitCode;

fn main() -> ExitCode {
    if jdc_authority_service::verify_service_identity().is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
