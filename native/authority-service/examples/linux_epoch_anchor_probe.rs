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
    if action == "policy-monitor-stdin" {
        use jdc_authority_service::linux_policy_epoch_monitor::PolicyEpochMonitor;
        use std::io::{BufRead, Write};
        // An event-driven, disposable CI process holds ONE monitor instance
        // while an independently privileged administrator changes the state.
        // This is a data-only proof: no filesystem operation is granted.
        let mut monitor = PolicyEpochMonitor::from_current_os_attested().unwrap_or_else(|_| {
            eprintln!("E_POLICY_MONITOR_INITIAL_DENIAL");
            std::process::exit(1);
        });
        let stdin = std::io::stdin();
        let mut incoming = stdin.lock();
        let mut out = std::io::stdout().lock();
        writeln!(out, "MONITOR_READY").unwrap();
        out.flush().unwrap();
        for _ in 0..3 {
            let mut line = String::new();
            if incoming.read_line(&mut line).unwrap_or(0) == 0 || line != "check\n" {
                eprintln!("E_POLICY_MONITOR_INVALID_HANDSHAKE");
                std::process::exit(1);
            }
            let answer = if monitor.revalidate_current().is_ok() {
                "MONITOR_MATCH"
            } else {
                "MONITOR_DENIED"
            };
            writeln!(out, "{answer}").unwrap();
            out.flush().unwrap();
        }
        return;
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
    if action == "policy-snapshot"
        || action == "policy-snapshot-v2"
        || action == "policy-snapshot-v3"
        || action == "policy-snapshot-v4"
    {
        let (expected_epoch, expected_bytes): (u64, &[u8]) = if action == "policy-snapshot-v4" {
            (4, b"approved-policy-fixture-v4")
        } else if action == "policy-snapshot-v3" {
            (3, b"approved-policy-fixture-v3")
        } else if action == "policy-snapshot-v2" {
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
