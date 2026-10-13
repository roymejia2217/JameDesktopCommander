//! Test-only synthetic policy fixture. Never part of a production broker.
use jdc_authority_store::EpochStore;
use rusqlite::Connection;
use std::{env, path::Path, process::ExitCode};

fn execute(command: &str, path: &Path) -> Result<(), String> {
    match command {
        "init" => {
            // Create a uniquely provisioned synthetic DB under a CI-owned
            // directory. Do not accept SQL or policy data from the caller.
            let conn = Connection::open(path).map_err(|e| e.to_string())?;
            conn.execute_batch(
                "PRAGMA application_id=0x4A444331;
                 PRAGMA user_version=1;
                 CREATE TABLE protected_policy (slot INTEGER PRIMARY KEY CHECK(slot=1), epoch BLOB NOT NULL CHECK(length(epoch)=8), digest BLOB NOT NULL CHECK(length(digest)=32));
                 INSERT INTO protected_policy(slot,epoch,digest) VALUES (1,zeroblob(8),zeroblob(32));",
            ).map_err(|e| e.to_string())?;
            drop(conn);
            let mut store = EpochStore::open_existing(path).map_err(|_| "store unavailable")?;
            store
                .commit_after(0, 1, [1; 32])
                .map_err(|_| "commit failed".to_string())?;
            Ok(())
        }
        "advance" => {
            let mut store = EpochStore::open_existing(path).map_err(|_| "store unavailable")?;
            store
                .commit_after(1, 2, [2; 32])
                .map_err(|_| "commit failed".to_string())
        }
        "verify-2" => {
            let store = EpochStore::open_existing(path).map_err(|_| "store unavailable")?;
            if store.read_epoch().map_err(|_| "read denied")? == 2 {
                Ok(())
            } else {
                Err("rollback detected".into())
            }
        }
        _ => Err("unsupported offline fixture command".into()),
    }
}

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let (Some(mode), Some(db), None) = (args.next(), args.next(), args.next()) else {
        eprintln!("E_FIXTURE_USAGE");
        return ExitCode::FAILURE;
    };
    let Some(mode) = mode.to_str() else {
        return ExitCode::FAILURE;
    };
    match execute(mode, Path::new(&db)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("E_FIXTURE_REJECTED");
            ExitCode::FAILURE
        }
    }
}
