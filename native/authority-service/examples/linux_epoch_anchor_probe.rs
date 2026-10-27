//! CI-only process entry for real root-admin Linux witness acceptance.
//! This example never provisions state, grants authority or accepts a path.
#[cfg(target_os = "linux")]
fn main() {
    use jdc_authority_service::linux_epoch_anchor::observe_fixed_epoch_floor;
    let mut args = std::env::args().skip(1);
    let action = args.next().unwrap_or_default();
    if args.next().is_some() {
        eprintln!("E_ANCHOR_INVALID_PROBE_ARGUMENTS");
        std::process::exit(2);
    }
    let observed = observe_fixed_epoch_floor();
    match action.as_str() {
        "match" => {
            if observed.is_ok_and(|floor| floor.matches_snapshot(1, &[0xA5; 32])) {
                println!("MATCH");
            } else {
                eprintln!("E_ANCHOR_AUTHORITY_MISMATCH");
                std::process::exit(1);
            }
        }
        "deny" => {
            if observed.is_err() {
                println!("DENIED");
            } else {
                eprintln!("E_ANCHOR_UNAUTHORIZED_OBSERVATION");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("E_ANCHOR_INVALID_PROBE_ACTION");
            std::process::exit(2);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {}
