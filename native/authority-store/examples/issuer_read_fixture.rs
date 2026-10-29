//! Disposable CI fixture for the Linux issuer-read E2E.
//! It creates data only; it never authenticates a caller or grants filesystem access.
use jdc_authority_store::policy_bytes::PolicyBytesStore;
use rusqlite::Connection;
use std::{env, path::Path, process::ExitCode};

const POLICY_EPOCH: u64 = 1;
const POLICY_BYTES: &[u8] = br#"{"version":1,"mode":"restricted","roots":[{"rootRef":"0123456789abcdef0123456789abcdef","absolutePath":"/var/lib/jdc-authority/read-root"}]}"#;

fn init_policy(path: &Path) -> Result<[u8; 32], String> {
    let db = Connection::open(path).map_err(|e| e.to_string())?;
    db.execute_batch(concat!(
        "PRAGMA application_id=0x4A444332; PRAGMA user_version=2;",
        "CREATE TABLE protected_policy (slot INTEGER PRIMARY KEY CHECK(slot=1), ",
        "epoch BLOB NOT NULL CHECK(length(epoch)=8), ",
        "digest BLOB NOT NULL CHECK(length(digest)=32), ",
        "policy_bytes BLOB NOT NULL CHECK(typeof(policy_bytes)='blob' AND length(policy_bytes)<=65536));",
        "INSERT INTO protected_policy(slot,epoch,digest,policy_bytes) ",
        "VALUES (1,zeroblob(8),zeroblob(32),x'');"
    ))
    .map_err(|e| e.to_string())?;
    drop(db);
    let mut store =
        PolicyBytesStore::open_existing(path).map_err(|_| "policy store unavailable")?;
    store
        .commit_after(0, POLICY_EPOCH, POLICY_BYTES)
        .map_err(|_| "policy commit denied")?;
    Ok(PolicyBytesStore::digest_exact(POLICY_BYTES))
}

fn init_replay(path: &Path) -> Result<(), String> {
    let db = Connection::open(path).map_err(|e| e.to_string())?;
    db.execute_batch(concat!(
        "PRAGMA journal_mode=DELETE; PRAGMA application_id=0x4A44434C; PRAGMA user_version=1;",
        "CREATE TABLE replay_claims (epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), ",
        "request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)=16), ",
        "PRIMARY KEY(epoch,request)) WITHOUT ROWID;"
    ))
    .map_err(|e| e.to_string())?;
    let check: String = db
        .pragma_query_value(None, "quick_check", |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if check != "ok" {
        return Err("replay fixture integrity check failed".into());
    }
    Ok(())
}
fn execute(policy: &Path, anchor: &Path, replay: &Path) -> Result<(), String> {
    for output in [policy, anchor, replay] {
        if output.exists() {
            return Err("fixture output already exists".into());
        }
    }
    let digest = init_policy(policy)?;
    let mut witness = Vec::with_capacity(40);
    witness.extend_from_slice(&POLICY_EPOCH.to_be_bytes());
    witness.extend_from_slice(&digest);
    std::fs::write(anchor, witness).map_err(|e| e.to_string())?;
    init_replay(replay)?;
    Ok(())
}

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let (Some(policy), Some(anchor), Some(replay), None) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        eprintln!("E_ISSUER_READ_FIXTURE_USAGE");
        return ExitCode::FAILURE;
    };
    match execute(Path::new(&policy), Path::new(&anchor), Path::new(&replay)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("E_ISSUER_READ_FIXTURE_REJECTED");
            ExitCode::FAILURE
        }
    }
}
