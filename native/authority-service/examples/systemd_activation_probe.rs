//! TEST ONLY: inspect inherited descriptors supplied by systemd-socket-activate.
//! This example is NOT a privileged broker, service or release binary.
#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use std::path::PathBuf;
    let Some(expected_path) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("E_ACTIVATION_EXPECTED_PATH_MISSING");
        return std::process::ExitCode::FAILURE;
    };
    if jdc_authority_service::unix_activation::inspect_inherited_systemd_listener(&expected_path)
        .is_err()
    {
        eprintln!("E_ACTIVATION_UNVERIFIED");
        return std::process::ExitCode::FAILURE;
    }
    println!("T011_SYSTEMD_FD3_NAMED_KERNEL_SHAPE_OBSERVED_NO_AUTHORITY");
    std::process::ExitCode::SUCCESS
}

#[cfg(not(target_os = "linux"))]
fn main() {}
