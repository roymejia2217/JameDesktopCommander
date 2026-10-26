use jdc_authority_store::EpochStore;
use rusqlite::Connection;
use std::path::Path;
use tempfile::tempdir;

fn fixture(db: &Path) {
    let conn = Connection::open(db).expect("fixture database");
    conn.execute_batch(
        "PRAGMA application_id=0x4A444331;
         PRAGMA user_version=1;
         CREATE TABLE protected_policy (slot INTEGER PRIMARY KEY CHECK(slot=1), epoch BLOB NOT NULL CHECK(length(epoch)=8), digest BLOB NOT NULL CHECK(length(digest)=32));
         INSERT INTO protected_policy(slot,epoch,digest) VALUES (1,zeroblob(8),zeroblob(32));",
    ).unwrap();
}
fn digest(value: u8) -> [u8; 32] {
    [value; 32]
}

#[test]
fn sqlite_readwrite_fallback_must_not_admit_readonly_store() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("readonly.sqlite3");
    fixture(&db);
    let original = std::fs::metadata(&db).unwrap().permissions();
    let mut readonly = original.clone();
    readonly.set_readonly(true);
    std::fs::set_permissions(&db, readonly).unwrap();
    // Always restore before asserting, including when the contract is RED.
    let admitted = EpochStore::open_existing(&db).is_ok();
    std::fs::set_permissions(&db, original).unwrap();
    assert!(
        !admitted,
        "SQLite's READWRITE flag can fall back to readonly"
    );
}

#[test]
fn store_fails_closed_if_unprovisioned_or_malformed() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("missing.sqlite3");
    assert!(EpochStore::open_existing(&missing).is_err());
    let malformed = dir.path().join("bad.sqlite3");
    std::fs::write(&malformed, b"not a sqlite database").unwrap();
    assert!(EpochStore::open_existing(&malformed).is_err());
}

#[test]
fn reopening_retains_epoch_and_rejects_old_or_equal_commit() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("state.sqlite3");
    fixture(&db);
    {
        let mut store = EpochStore::open_existing(&db).unwrap();
        assert!(store.commit_after(0, 7, digest(9)).is_ok());
        assert!(store.commit_after(0, 8, digest(10)).is_err());
        assert!(store.commit_after(7, 7, digest(11)).is_err());
        assert!(store.commit_after(7, 8, digest(12)).is_ok());
    }
    let mut reopened = EpochStore::open_existing(&db).unwrap();
    assert_eq!(reopened.read_epoch().unwrap(), 8);
    assert!(reopened.commit_after(7, 9, digest(13)).is_err());
    assert!(reopened.commit_after(8, 9, digest(14)).is_ok());
}

#[test]
fn snapshot_preserves_exact_epoch_and_digest_without_granting_authority() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("state.sqlite3");
    fixture(&db);
    let mut store = EpochStore::open_existing(&db).unwrap();
    assert!(
        store.read_snapshot().is_err(),
        "unprovisioned all-zero fixture must deny"
    );
    assert!(store.commit_after(0, 7, [0xA5; 32]).is_ok());
    let snapshot = store.read_snapshot().unwrap();
    assert_eq!(snapshot.epoch(), 7);
    assert_eq!(snapshot.digest(), &[0xA5; 32]);
    // Matching a synthetic witness is data comparison only. No OS evidence.
    assert_eq!((snapshot.epoch(), snapshot.digest()), (7, &[0xA5; 32]));
}

#[test]
fn database_replay_and_same_epoch_digest_change_do_not_match_separate_witness() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("state.sqlite3");
    let saved = dir.path().join("saved.sqlite3");
    fixture(&db);
    {
        let mut store = EpochStore::open_existing(&db).unwrap();
        store.commit_after(0, 1, [1; 32]).unwrap();
    }
    std::fs::copy(&db, &saved).unwrap();
    {
        let mut store = EpochStore::open_existing(&db).unwrap();
        store.commit_after(1, 2, [2; 32]).unwrap();
        let current = store.read_snapshot().unwrap();
        assert_eq!((current.epoch(), current.digest()), (2, &[2; 32]));
    }
    std::fs::copy(&saved, &db).unwrap();
    let rollback = EpochStore::open_existing(&db)
        .unwrap()
        .read_snapshot()
        .unwrap();
    assert_ne!((rollback.epoch(), rollback.digest()), (2, &[2; 32]));
    // A digest-only substitution at the same epoch must not be accepted.
    {
        let mut store = EpochStore::open_existing(&db).unwrap();
        store.commit_after(1, 2, [0xA6; 32]).unwrap();
    }
    let forged = EpochStore::open_existing(&db)
        .unwrap()
        .read_snapshot()
        .unwrap();
    assert_eq!(forged.epoch(), 2);
    assert_ne!(forged.digest(), &[2; 32]);
}

#[test]
fn corrupted_previous_policy_must_not_be_laundered_by_epoch_advance() {
    for (previous_epoch, corrupt_digest) in [(0_u64, [7_u8; 32]), (1_u64, [0_u8; 32])] {
        let dir = tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");
        fixture(&db);
        if previous_epoch == 1 {
            EpochStore::open_existing(&db)
                .unwrap()
                .commit_after(0, 1, [1_u8; 32])
                .unwrap();
        }
        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE protected_policy SET digest=?1 WHERE slot=1",
            [corrupt_digest.as_slice()],
        )
        .unwrap();
        drop(conn);
        let mut store = EpochStore::open_existing(&db).unwrap();
        assert!(
            store
                .commit_after(previous_epoch, previous_epoch + 1, [2_u8; 32])
                .is_err(),
            "updater must never overwrite an invalid prior row"
        );
        assert_eq!(store.read_epoch().unwrap(), previous_epoch);
    }
}

#[test]
fn schema_change_after_open_must_deny_before_writing() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("state.sqlite3");
    fixture(&db);
    let mut store = EpochStore::open_existing(&db).unwrap();
    let attacker = Connection::open(&db).unwrap();
    attacker
        .execute_batch(
            "CREATE TRIGGER unexpected AFTER UPDATE ON protected_policy BEGIN SELECT 1; END;",
        )
        .unwrap();
    drop(attacker);
    assert!(
        store.commit_after(0, 1, [2_u8; 32]).is_err(),
        "after-open trigger change must be rejected, never used as an update side effect"
    );
    assert!(
        store.read_epoch().is_err(),
        "schema drift must deny all store readers"
    );
    let raw_epoch: Vec<u8> = Connection::open(&db)
        .unwrap()
        .query_row("SELECT epoch FROM protected_policy WHERE slot=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        raw_epoch, [0_u8; 8],
        "rejected write must preserve original epoch"
    );
}

#[test]
fn opened_reader_must_refuse_post_open_schema_mutation() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("state.sqlite3");
    fixture(&db);
    let mut store = EpochStore::open_existing(&db).unwrap();
    store.commit_after(0, 1, [5_u8; 32]).unwrap();
    assert_eq!(store.read_snapshot().unwrap().epoch(), 1);
    let other = Connection::open(&db).unwrap();
    other
        .execute_batch(
            "CREATE TRIGGER unexpected AFTER UPDATE ON protected_policy BEGIN SELECT 1; END;",
        )
        .unwrap();
    drop(other);
    assert!(store.read_epoch().is_err(), "read_epoch must reject drift");
    assert!(
        store.read_snapshot().is_err(),
        "read_snapshot must reject drift"
    );
}

#[test]
fn store_refuses_to_commit_all_zero_policy_digest() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("state.sqlite3");
    fixture(&db);
    let mut store = EpochStore::open_existing(&db).unwrap();
    assert!(store.commit_after(0, 1, [0; 32]).is_err());
    assert_eq!(store.read_epoch().unwrap(), 0);
}

#[test]
fn concurrent_transactions_have_exactly_one_winner() {
    use std::sync::{Arc, Barrier};
    let dir = tempdir().unwrap();
    let db = dir.path().join("state.sqlite3");
    fixture(&db);
    let gate = Arc::new(Barrier::new(2));
    let (a, b) = std::thread::scope(|scope| {
        let gate1 = Arc::clone(&gate);
        let gate2 = Arc::clone(&gate);
        let db1 = db.clone();
        let db2 = db.clone();
        let first = scope.spawn(move || {
            let mut s = EpochStore::open_existing(&db1).unwrap();
            gate1.wait();
            s.commit_after(0, 1, digest(1))
        });
        let second = scope.spawn(move || {
            let mut s = EpochStore::open_existing(&db2).unwrap();
            gate2.wait();
            s.commit_after(0, 1, digest(2))
        });
        (
            first.join().unwrap().is_ok(),
            second.join().unwrap().is_ok(),
        )
    });
    assert_ne!(a, b);
    assert_eq!(
        EpochStore::open_existing(&db)
            .unwrap()
            .read_epoch()
            .unwrap(),
        1
    );
}

#[test]
fn whole_database_replay_is_still_possible_without_os_protected_custody() {
    // NEGATIVE PROOF: atomic SQLite transactions alone do not protect history
    // if a configuration editor can replace the entire database file.
    let dir = tempdir().unwrap();
    let db = dir.path().join("state.sqlite3");
    let saved = dir.path().join("saved.sqlite3");
    fixture(&db);
    {
        let mut s = EpochStore::open_existing(&db).unwrap();
        s.commit_after(0, 1, digest(1)).unwrap();
    }
    std::fs::copy(&db, &saved).unwrap();
    {
        let mut s = EpochStore::open_existing(&db).unwrap();
        s.commit_after(1, 2, digest(2)).unwrap();
    }
    std::fs::copy(&saved, &db).unwrap();
    assert_eq!(
        EpochStore::open_existing(&db)
            .unwrap()
            .read_epoch()
            .unwrap(),
        1,
        "a file-controlling adversary CAN rewind an unprotected SQLite store"
    );
}

#[test]
fn rejects_unmarked_or_extended_database_schemas() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("state.sqlite3");
    fixture(&db);
    let conn = Connection::open(&db).unwrap();
    conn.execute_batch("PRAGMA application_id=0;").unwrap();
    assert!(
        EpochStore::open_existing(&db).is_err(),
        "unknown database format must deny"
    );
    conn.execute_batch("PRAGMA application_id=0x4A444331; PRAGMA user_version=2;")
        .unwrap();
    assert!(
        EpochStore::open_existing(&db).is_err(),
        "unsupported schema must deny"
    );
    conn.execute_batch("PRAGMA user_version=1; CREATE TRIGGER unexpected AFTER UPDATE ON protected_policy BEGIN SELECT 1; END;").unwrap();
    assert!(
        EpochStore::open_existing(&db).is_err(),
        "unexpected triggers must deny"
    );
    conn.execute_batch("DROP TRIGGER unexpected; DROP TABLE protected_policy; CREATE TABLE protected_policy(slot INTEGER PRIMARY KEY, epoch BLOB NOT NULL, digest BLOB NOT NULL); INSERT INTO protected_policy VALUES(1,zeroblob(8),zeroblob(32));").unwrap();
    assert!(
        EpochStore::open_existing(&db).is_err(),
        "weakened schema constraints must deny"
    );
}

#[test]
fn supports_unsigned_u64_epoch_without_integer_truncation() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("max.sqlite3");
    fixture(&db);
    {
        let mut s = EpochStore::open_existing(&db).unwrap();
        assert!(s.commit_after(0, u64::MAX, digest(1)).is_ok());
    }
    let mut s = EpochStore::open_existing(&db).unwrap();
    assert_eq!(s.read_epoch().unwrap(), u64::MAX);
    assert!(s.commit_after(u64::MAX, 1, digest(2)).is_err());
}
