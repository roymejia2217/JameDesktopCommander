//! CI-only root-admin publication begin acceptance. Never packaged or
//! installed as a service, never finishes a policy update or grants access.
#[cfg(target_os = "linux")]
fn main() {
    let mut args = std::env::args().skip(1);
    let action = args.next().unwrap_or_default();
    match action.as_str() {
        "begin" if args.next().is_none() => {
            if jdc_authority_service::linux_policy_publisher::begin_fixed_publication().is_err() {
                eprintln!("E_PUBLISHER_ADMIN_ONLY_OR_ALREADY_IN_PROGRESS");
                std::process::exit(1);
            }
            println!("PUBLISH_INTENT_CREATED");
        }
        "recover-completed" if args.next().is_none() => {
            if jdc_authority_service::linux_policy_publisher::recover_after_witness_rename()
                .is_err()
            {
                eprintln!("E_PUBLISHER_COMPLETED_RECOVERY_DENIED");
                std::process::exit(1);
            }
            println!("PUBLISH_COMPLETED_RECOVERED");
        }
        "recover-split" if args.next().is_none() => {
            if jdc_authority_service::linux_policy_publisher::recover_after_policy_rename().is_err()
            {
                eprintln!("E_PUBLISHER_RECOVERY_STATE_DENIED");
                std::process::exit(1);
            }
            println!("PUBLISH_SPLIT_RECOVERED");
        }
        "prepare-v3" | "prepare-v4" => {
            // Only this CI-only example accepts an ephemeral fixture path.
            // Root publisher APIs take verified in-memory bytes, not paths.
            let source = args.next().unwrap_or_default();
            if source.is_empty() || args.next().is_some() {
                std::process::exit(2);
            }
            let bytes = std::fs::read(source).unwrap_or_else(|_| {
                eprintln!("E_PUBLISHER_CI_FIXTURE_UNREADABLE");
                std::process::exit(1);
            });
            if jdc_authority_service::linux_policy_publisher::prepare_fixed_publication(&bytes)
                .is_err()
            {
                eprintln!("E_PUBLISHER_PREPARE_DENIED");
                std::process::exit(1);
            }
            println!("PUBLISH_PREPARED");
        }
        "commit-v2" => {
            // CI-only: source is a synthetic SQLite v2 fixture in an
            // ephemeral runner. No production updater accepts a path.
            let source = args.next().unwrap_or_default();
            if source.is_empty() || args.next().is_some() {
                std::process::exit(2);
            }
            let bytes = std::fs::read(source).unwrap_or_else(|_| {
                eprintln!("E_PUBLISHER_CI_FIXTURE_UNREADABLE");
                std::process::exit(1);
            });
            if jdc_authority_service::linux_policy_publisher::commit_fixed_publication(&bytes)
                .is_err()
            {
                eprintln!("E_PUBLISHER_COMMIT_DENIED");
                std::process::exit(1);
            }
            println!("PUBLISH_COMMITTED");
        }
        _ => {
            eprintln!("E_PUBLISHER_INVALID_CI_ACTION");
            std::process::exit(2);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {}
