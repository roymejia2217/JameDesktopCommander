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
