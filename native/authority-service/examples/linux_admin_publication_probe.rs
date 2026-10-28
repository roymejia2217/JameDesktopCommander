//! CI-only root-admin publication begin acceptance. Never packaged or
//! installed as a service, never finishes a policy update or grants access.
#[cfg(target_os = "linux")]
fn main() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("begin") || args.next().is_some() {
        eprintln!("E_PUBLISHER_INVALID_CI_ACTION");
        std::process::exit(2);
    }
    if jdc_authority_service::linux_policy_publisher::begin_fixed_publication().is_err() {
        eprintln!("E_PUBLISHER_ADMIN_ONLY_OR_ALREADY_IN_PROGRESS");
        std::process::exit(1);
    }
    println!("PUBLISH_INTENT_CREATED");
}

#[cfg(not(target_os = "linux"))]
fn main() {}
