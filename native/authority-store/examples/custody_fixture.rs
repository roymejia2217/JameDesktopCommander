//! Test-only synthetic policy fixture. Never part of a production broker.
use jdc_authority_store::EpochStore;
use rusqlite::Connection;
use std::{env, path::Path, process::ExitCode};

// Canonical issuer-v1 restricted policies. These are synthetic, test-only
// administrator candidate bytes; none grants authority without OS custody.
fn approved_policy(epoch: u64) -> &'static [u8] {
    match epoch {
        1 => include_bytes!("../../../test/security/fixtures/t011-admin-policy-v1.json"),
        2 => include_bytes!("../../../test/security/fixtures/t011-admin-policy-v2.json"),
        3 => include_bytes!("../../../test/security/fixtures/t011-admin-policy-v3.json"),
        4 => include_bytes!("../../../test/security/fixtures/t011-admin-policy-v4.json"),
        5 => include_bytes!("../../../test/security/fixtures/t011-admin-policy-v5.json"),
        _ => unreachable!("test-only fixture must use an enumerated epoch"),
    }
}

// CI-only proof of a genuine SQLite rollback journal, not a manufactured sidecar.
fn prove_rollback_journal(path: &Path) -> Result<(), String> {
    let mut journal_name = path.as_os_str().to_os_string();
    journal_name.push("-journal");
    let journal = std::path::PathBuf::from(journal_name);
    if journal.exists() {
        return Err("preexisting rollback journal".into());
    }
    let mut conn = Connection::open(path).map_err(|e| e.to_string())?;
    if conn
        .is_readonly(rusqlite::MAIN_DB)
        .map_err(|e| e.to_string())?
    {
        return Err("read-only database".into());
    }
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err("unexpected SQLite journal mode".into());
    }
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let modified = tx
        .execute(
            "UPDATE protected_policy SET digest = ?1 WHERE slot = 1",
            rusqlite::params![[0x5Au8; 32].as_slice()],
        )
        .map_err(|e| e.to_string())?;
    if modified != 1 || !journal.is_file() {
        return Err("SQLite did not create its rollback journal".into());
    }
    tx.rollback().map_err(|e| e.to_string())?;
    if journal.exists() {
        return Err("rollback journal remained after rollback".into());
    }
    Ok(())
}

fn execute(command: &str, path: &Path) -> Result<(), String> {
    match command {
        "write-policy-anchor-mismatch" => {
            let mut bytes = Vec::with_capacity(40);
            bytes.extend_from_slice(&1u64.to_be_bytes());
            bytes.extend_from_slice(&[0x33u8; 32]);
            std::fs::write(path, bytes).map_err(|e| e.to_string())
        }
        "write-policy-anchor"
        | "write-policy-anchor-v2"
        | "write-policy-anchor-v3"
        | "write-policy-anchor-v4"
        | "write-policy-anchor-v5" => {
            let epoch = if command.ends_with("-v5") {
                5
            } else if command.ends_with("-v4") {
                4
            } else if command.ends_with("-v3") {
                3
            } else if command.ends_with("-v2") {
                2
            } else {
                1
            };
            let policy = approved_policy(epoch);
            let mut bytes = Vec::with_capacity(40);
            bytes.extend_from_slice(&epoch.to_be_bytes());
            bytes.extend_from_slice(
                &jdc_authority_store::policy_bytes::PolicyBytesStore::digest_exact(policy),
            );
            std::fs::write(path, bytes).map_err(|e| e.to_string())
        }
        "init-policy-bytes"
        | "init-policy-bytes-v2"
        | "init-policy-bytes-v3"
        | "init-policy-bytes-v4"
        | "init-policy-bytes-v5"
        | "init-policy-bytes-invalid-v2" => {
            use jdc_authority_store::policy_bytes::PolicyBytesStore;
            let epoch = if command.ends_with("-v5") {
                5
            } else if command.ends_with("-v4") {
                4
            } else if command.ends_with("-v3") {
                3
            } else if command.ends_with("-v2") {
                2
            } else {
                1
            };
            let policy = if command == "init-policy-bytes-invalid-v2" {
                // Internally digest-consistent, but NOT an issuer-v1 policy.
                // Only the real root-admin publisher must reject this image.
                b"approved-policy-fixture-v2".as_slice()
            } else {
                approved_policy(epoch)
            };
            let conn = Connection::open(path).map_err(|e| e.to_string())?;
            conn.execute_batch(
                "PRAGMA application_id=0x4A444332;
                 PRAGMA user_version=2;
                 CREATE TABLE protected_policy (slot INTEGER PRIMARY KEY CHECK(slot=1), epoch BLOB NOT NULL CHECK(length(epoch)=8), digest BLOB NOT NULL CHECK(length(digest)=32), policy_bytes BLOB NOT NULL CHECK(typeof(policy_bytes)='blob' AND length(policy_bytes)<=65536));
                 INSERT INTO protected_policy(slot,epoch,digest,policy_bytes) VALUES (1,zeroblob(8),zeroblob(32),x'');",
            ).map_err(|e| e.to_string())?;
            drop(conn);
            let mut store =
                PolicyBytesStore::open_existing(path).map_err(|_| "store unavailable")?;
            store
                .commit_after(0, epoch, policy)
                .map_err(|_| "policy fixture commit unavailable".into())
        }
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
        "prove-rollback-journal" => prove_rollback_journal(path),
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

#[cfg(test)]
mod tests {
    use super::{approved_policy, execute};
    use tempfile::tempdir;

    #[test]
    fn independent_admin_witness_fixture_matches_exact_policy_bytes() {
        let d = tempdir().unwrap();
        let file = d.path().join("root-anchor");
        execute("write-policy-anchor", &file).unwrap();
        let bytes = std::fs::read(&file).unwrap();
        assert_eq!(bytes.len(), 40);
        assert_eq!(&bytes[..8], &1u64.to_be_bytes());
        assert_eq!(
            &bytes[8..],
            &jdc_authority_store::policy_bytes::PolicyBytesStore::digest_exact(approved_policy(1))
        );
    }
    #[test]
    fn independent_epoch_five_fixture_is_forward_and_digest_bound() {
        let d = tempdir().unwrap();
        let image = d.path().join("v5.sqlite3");
        let witness = d.path().join("witness-v5");
        execute("init-policy-bytes-v5", &image).unwrap();
        execute("write-policy-anchor-v5", &witness).unwrap();
        let policy = jdc_authority_store::policy_bytes::PolicyBytesStore::read_verified_serialized(
            &std::fs::read(&image).unwrap(),
        )
        .unwrap();
        assert_eq!(policy.epoch(), 5);
        assert_eq!(policy.bytes(), approved_policy(5));
        let wire = std::fs::read(&witness).unwrap();
        assert_eq!(wire.len(), 40);
        assert_eq!(&wire[..8], &5u64.to_be_bytes());
        assert_eq!(&wire[8..], policy.digest());
    }

    #[test]
    fn independent_epoch_four_fixture_is_forward_and_digest_bound() {
        let d = tempdir().unwrap();
        let image = d.path().join("v4.sqlite3");
        let witness = d.path().join("witness-v4");
        execute("init-policy-bytes-v4", &image).unwrap();
        execute("write-policy-anchor-v4", &witness).unwrap();
        let policy = jdc_authority_store::policy_bytes::PolicyBytesStore::read_verified_serialized(
            &std::fs::read(&image).unwrap(),
        )
        .unwrap();
        assert_eq!(policy.epoch(), 4);
        assert_eq!(policy.bytes(), approved_policy(4));
        let wire = std::fs::read(&witness).unwrap();
        assert_eq!(wire.len(), 40);
        assert_eq!(&wire[..8], &4u64.to_be_bytes());
        assert_eq!(&wire[8..], policy.digest());
    }

    #[test]
    fn independent_epoch_three_fixture_is_forward_and_digest_bound() {
        let d = tempdir().unwrap();
        let image = d.path().join("v3.sqlite3");
        let witness = d.path().join("witness-v3");
        execute("init-policy-bytes-v3", &image).unwrap();
        execute("write-policy-anchor-v3", &witness).unwrap();
        let policy = jdc_authority_store::policy_bytes::PolicyBytesStore::read_verified_serialized(
            &std::fs::read(&image).unwrap(),
        )
        .unwrap();
        assert_eq!(policy.epoch(), 3);
        assert_eq!(policy.bytes(), approved_policy(3));
        let wire = std::fs::read(&witness).unwrap();
        assert_eq!(wire.len(), 40);
        assert_eq!(&wire[..8], &3u64.to_be_bytes());
        assert_eq!(&wire[8..], policy.digest());
    }

    #[test]
    fn independent_admin_epoch_two_fixture_differs_from_epoch_one() {
        use jdc_authority_store::policy_bytes::PolicyBytesStore;
        let d = tempdir().unwrap();
        let old = d.path().join("old-policy.sqlite3");
        let new = d.path().join("new-policy.sqlite3");
        let witness = d.path().join("new-witness");
        execute("init-policy-bytes", &old).unwrap();
        execute("init-policy-bytes-v2", &new).unwrap();
        execute("write-policy-anchor-v2", &witness).unwrap();
        let old_snapshot =
            PolicyBytesStore::read_verified_serialized(&std::fs::read(old).unwrap()).unwrap();
        let new_snapshot =
            PolicyBytesStore::read_verified_serialized(&std::fs::read(new).unwrap()).unwrap();
        assert_eq!(old_snapshot.epoch(), 1);
        assert_eq!(new_snapshot.epoch(), 2);
        assert_ne!(old_snapshot.digest(), new_snapshot.digest());
        assert_eq!(new_snapshot.bytes(), approved_policy(2));
        let bytes = std::fs::read(witness).unwrap();
        assert_eq!(bytes.len(), 40);
        assert_eq!(&bytes[..8], &2u64.to_be_bytes());
        assert_eq!(&bytes[8..], new_snapshot.digest());
        assert_ne!(&bytes[8..], old_snapshot.digest());
    }

    #[test]
    fn v2_fixture_produces_actual_immutable_policy_image() {
        let d = tempdir().unwrap();
        let p = d.path().join("approved.sqlite3");
        execute("init-policy-bytes", &p).unwrap();
        let data = std::fs::read(&p).unwrap();
        let observed =
            jdc_authority_store::policy_bytes::PolicyBytesStore::read_verified_serialized(&data)
                .unwrap();
        assert_eq!(observed.epoch(), 1);
        assert_eq!(observed.bytes(), approved_policy(1));
    }
    #[test]
    fn actual_sqlite_rollback_journal_is_created_and_removed_without_epoch_change() {
        let directory = tempdir().unwrap();
        let db = directory.path().join("policy.sqlite3");
        execute("init", &db).unwrap();
        execute("advance", &db).unwrap();
        execute("prove-rollback-journal", &db).unwrap();
        execute("verify-2", &db).unwrap();
        let snapshot = jdc_authority_store::EpochStore::open_existing(&db)
            .unwrap()
            .read_snapshot()
            .unwrap();
        assert_eq!(snapshot.digest(), &[2; 32], "rollback changed policy bytes");
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
