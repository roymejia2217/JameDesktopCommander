//! CI-only process entry for real root-admin Linux witness acceptance.
//! This example never provisions state, grants authority or accepts a path.
#[cfg(target_os = "linux")]
fn main() {
    use jdc_authority_service::linux_epoch_anchor::{
        observe_fixed_epoch_floor, observe_fixed_policy_database,
        observe_matching_admin_policy_snapshot,
    };
    let mut args = std::env::args().skip(1);
    let action = args.next().unwrap_or_default();
    if args.next().is_some() {
        eprintln!("E_ANCHOR_INVALID_PROBE_ARGUMENTS");
        std::process::exit(2);
    }
    if action == "policy-snapshot-deny" {
        if observe_matching_admin_policy_snapshot().is_err() {
            println!("DENIED");
        } else {
            eprintln!("E_ADMIN_POLICY_WITNESS_NOT_ENFORCED");
            std::process::exit(1);
        }
        return;
    }
    if action == "policy-snapshot" || action == "policy-snapshot-v2" {
        let (expected_epoch, expected_bytes): (u64, &[u8]) = if action == "policy-snapshot-v2" {
            (2, b"approved-policy-fixture-v2")
        } else {
            (1, b"approved-policy-fixture")
        };
        let result = observe_matching_admin_policy_snapshot();
        if result.is_ok_and(|policy| {
            policy.epoch() == expected_epoch
                && policy.bytes() == expected_bytes
                && policy.digest()
                    == &jdc_authority_store::policy_bytes::PolicyBytesStore::digest_exact(
                        expected_bytes,
                    )
        }) {
            println!("VERIFIED_BYTES");
        } else {
            eprintln!("E_ADMIN_POLICY_SNAPSHOT_MISMATCH");
            std::process::exit(1);
        }
        return;
    }
    if action == "policy-candidate" || action == "policy-deny" {
        let observed = observe_fixed_policy_database();
        match action.as_str() {
            "policy-candidate" if observed.is_ok() => println!("CANDIDATE"),
            "policy-deny" if observed.is_err() => println!("DENIED"),
            _ => {
                eprintln!("E_POLICY_CUSTODY_REJECTED");
                std::process::exit(1);
            }
        }
        return;
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
