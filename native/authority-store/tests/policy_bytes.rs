use jdc_authority_store::policy_bytes::PolicyBytesStore;
use rusqlite::Connection;
use std::path::Path;
use tempfile::tempdir;

const SCHEMA: &str = "CREATE TABLE protected_policy (slot INTEGER PRIMARY KEY CHECK(slot=1), epoch BLOB NOT NULL CHECK(length(epoch)=8), digest BLOB NOT NULL CHECK(length(digest)=32), policy_bytes BLOB NOT NULL CHECK(typeof(policy_bytes)='blob' AND length(policy_bytes)<=65536))";
fn fixture(path: &Path) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("PRAGMA application_id=0x4A444332; PRAGMA user_version=2;")
        .unwrap();
    db.execute_batch(SCHEMA).unwrap();
    db.execute("INSERT INTO protected_policy(slot,epoch,digest,policy_bytes) VALUES(1,zeroblob(8),zeroblob(32),?1)", [b"".as_slice()]).unwrap();
}
#[test]
fn immutable_sqlite_image_recovers_exact_policy_without_reopening_its_path() {
    let f = tempdir().unwrap();
    let path = f.path().join("policy.db");
    fixture(&path);
    let policy = b"approved exact policy bytes";
    PolicyBytesStore::open_existing(&path)
        .unwrap()
        .commit_after(0, 7, policy)
        .unwrap();
    let image = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let mut memory = Connection::open_in_memory().unwrap();
    memory
        .deserialize_read_exact(
            rusqlite::MAIN_DB,
            std::io::Cursor::new(image.as_slice()),
            image.len(),
            true,
        )
        .unwrap();
    assert!(
        memory
            .execute(
                "UPDATE protected_policy SET policy_bytes=x'00' WHERE slot=1",
                []
            )
            .is_err(),
        "deserialized policy image must be physically immutable"
    );
    let app: i64 = memory
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .unwrap();
    let version: i64 = memory
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!((app, version), (0x4A444332, 2));
    let observed = PolicyBytesStore::read_verified_serialized(&image).unwrap();
    assert_eq!(observed.epoch(), 7);
    assert_eq!(observed.digest(), &PolicyBytesStore::digest_exact(policy));
    assert_eq!(observed.bytes(), policy);
}
#[test]
fn immutable_sqlite_image_rejects_corruption_truncation_and_oversized_buffers() {
    let f = tempdir().unwrap();
    let path = f.path().join("policy.db");
    fixture(&path);
    PolicyBytesStore::open_existing(&path)
        .unwrap()
        .commit_after(0, 7, b"unique-policy-marker")
        .unwrap();
    let image = std::fs::read(&path).unwrap();
    for invalid in [
        Vec::new(),
        b"SQLite format 3\0".to_vec(),
        image[..image.len() - 1].to_vec(),
        vec![0u8; 4 * 1024 * 1024 + 1],
    ] {
        assert!(PolicyBytesStore::read_verified_serialized(&invalid).is_err());
    }
    let mut altered = image.clone();
    let marker = b"unique-policy-marker";
    let offset = altered
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("actual policy bytes must exist in SQLite fixture");
    altered[offset] ^= 0x01;
    assert!(PolicyBytesStore::read_verified_serialized(&altered).is_err());
}
#[test]
fn policy_bytes_roundtrip_and_nist_sha256_known_answer() {
    let f = tempdir().unwrap();
    let db = f.path().join("policy.db");
    fixture(&db);
    let mut store = PolicyBytesStore::open_existing(&db).unwrap();
    assert!(store.read_verified().is_err());
    let bytes = br#"{"version":1,"denyAll":true}"#;
    store.commit_after(0, 1, bytes).unwrap();
    drop(store);
    let reopened = PolicyBytesStore::open_existing(&db).unwrap();
    let result = reopened.read_verified().unwrap();
    assert_eq!(result.epoch(), 1);
    assert_eq!(result.bytes(), bytes);
    assert_eq!(result.digest(), &PolicyBytesStore::digest_exact(bytes));
    assert_eq!(
        PolicyBytesStore::digest_exact(b"abc"),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
}
#[test]
fn tampering_stored_policy_bytes_without_digest_denies_on_reopen_and_read() {
    let f = tempdir().unwrap();
    let db = f.path().join("policy.db");
    fixture(&db);
    let mut store = PolicyBytesStore::open_existing(&db).unwrap();
    store.commit_after(0, 7, b"genuine bytes").unwrap();
    let attacker = Connection::open(&db).unwrap();
    attacker
        .execute(
            "UPDATE protected_policy SET policy_bytes=?1",
            [b"forged bytes".as_slice()],
        )
        .unwrap();
    assert!(store.read_verified().is_err());
    drop(store);
    assert!(PolicyBytesStore::open_existing(&db).is_err());
}
#[test]
fn rejects_invalid_epoch_sizes_and_schema_extensions() {
    let f = tempdir().unwrap();
    let db = f.path().join("policy.db");
    fixture(&db);
    let mut store = PolicyBytesStore::open_existing(&db).unwrap();
    assert!(store.commit_after(0, 1, b"").is_err());
    assert!(store.commit_after(0, 1, &vec![5; 65537]).is_err());
    assert!(store.commit_after(0, 0, b"valid").is_err());
    store.commit_after(0, 7, &vec![9; 65536]).unwrap();
    assert!(store.commit_after(0, 8, b"stale").is_err());
    assert!(store.commit_after(7, 7, b"same epoch").is_err());
    assert_eq!(store.read_verified().unwrap().bytes().len(), 65536);
    drop(store);
    let attacker = Connection::open(&db).unwrap();
    attacker
        .execute_batch(
            "CREATE TRIGGER unexpected AFTER UPDATE ON protected_policy BEGIN SELECT 1; END;",
        )
        .unwrap();
    assert!(PolicyBytesStore::open_existing(&db).is_err());
}
#[test]
fn two_epoch_writers_have_exactly_one_winner() {
    use std::sync::{Arc, Barrier};
    let f = tempdir().unwrap();
    let db = f.path().join("policy.db");
    fixture(&db);
    let barrier = Arc::new(Barrier::new(2));
    let outcomes = std::thread::scope(|scope| {
        let workers: Vec<_> = [b"alpha".as_slice(), b"omega".as_slice()]
            .into_iter()
            .map(|bytes| {
                let db = db.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let mut s = PolicyBytesStore::open_existing(&db).unwrap();
                    barrier.wait();
                    s.commit_after(0, 1, bytes).is_ok()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(outcomes.into_iter().filter(|&ok| ok).count(), 1);
    assert_eq!(
        PolicyBytesStore::open_existing(&db)
            .unwrap()
            .read_verified()
            .unwrap()
            .epoch(),
        1
    );
}
#[test]
fn v2_denies_post_open_schema_drift_and_oversized_blob_without_overwriting() {
    let f = tempdir().unwrap();
    let db = f.path().join("policy.db");
    fixture(&db);
    let mut store = PolicyBytesStore::open_existing(&db).unwrap();
    store.commit_after(0, 3, b"approved-looking bytes").unwrap();
    let attacker = Connection::open(&db).unwrap();
    attacker
        .execute_batch(
            "CREATE TRIGGER unexpected AFTER UPDATE ON protected_policy BEGIN SELECT 1; END;",
        )
        .unwrap();
    assert!(store.read_verified().is_err());
    assert!(store.commit_after(3, 4, b"untrusted").is_err());
    attacker
        .execute_batch("DROP TRIGGER unexpected; PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    attacker
        .execute(
            "UPDATE protected_policy SET policy_bytes=zeroblob(1048576)",
            [],
        )
        .unwrap();
    assert!(store.read_verified().is_err());
    assert!(store.commit_after(3, 4, b"untrusted").is_err());
    drop(attacker);
    assert!(PolicyBytesStore::open_existing(&db).is_err());
}
#[test]
fn v1_and_v2_formats_do_not_auto_migrate_into_each_other() {
    let f = tempdir().unwrap();
    let db = f.path().join("policy.db");
    fixture(&db);
    assert!(jdc_authority_store::EpochStore::open_existing(&db).is_err());
    let attacker = Connection::open(&db).unwrap();
    attacker.execute_batch("PRAGMA user_version=1;").unwrap();
    drop(attacker);
    assert!(PolicyBytesStore::open_existing(&db).is_err());
}

#[test]
fn independently_held_snapshot_identity_denies_rollback_and_same_epoch_forgery() {
    let f = tempdir().unwrap();
    let db = f.path().join("policy.db");
    let old = f.path().join("old.db");
    fixture(&db);
    {
        let mut store = PolicyBytesStore::open_existing(&db).unwrap();
        store.commit_after(0, 1, b"old").unwrap();
    }
    std::fs::copy(&db, &old).unwrap();
    let approved = b"current approved bytes";
    let trusted_epoch = 2;
    let trusted_digest = PolicyBytesStore::digest_exact(approved);
    {
        let mut store = PolicyBytesStore::open_existing(&db).unwrap();
        store.commit_after(1, trusted_epoch, approved).unwrap();
        assert_eq!(
            store
                .read_matching_witness(trusted_epoch, &trusted_digest)
                .unwrap()
                .bytes(),
            approved
        );
        assert!(store
            .read_matching_witness(trusted_epoch, &[0xA5; 32])
            .is_err());
    }
    std::fs::copy(&old, &db).unwrap();
    let mut rolled = PolicyBytesStore::open_existing(&db).unwrap();
    assert!(rolled
        .read_matching_witness(trusted_epoch, &trusted_digest)
        .is_err());
    rolled
        .commit_after(1, trusted_epoch, b"forged at same epoch")
        .unwrap();
    assert!(rolled
        .read_matching_witness(trusted_epoch, &trusted_digest)
        .is_err());
    // The witness MUST be obtained from an independent trusted updater.
    // Supplying a caller-chosen matching pair is NOT authenticity.
}

#[test]
fn valid_whole_database_rollback_is_undetectable_without_independent_witness() {
    let f = tempdir().unwrap();
    let db = f.path().join("policy.db");
    let previous = f.path().join("previous.db");
    fixture(&db);
    {
        let mut s = PolicyBytesStore::open_existing(&db).unwrap();
        s.commit_after(0, 1, b"old valid bytes").unwrap();
    }
    std::fs::copy(&db, &previous).unwrap();
    {
        let mut s = PolicyBytesStore::open_existing(&db).unwrap();
        s.commit_after(1, 2, b"new valid bytes").unwrap();
    }
    std::fs::copy(&previous, &db).unwrap();
    let restored = PolicyBytesStore::open_existing(&db)
        .unwrap()
        .read_verified()
        .unwrap();
    assert_eq!(restored.epoch(), 1);
    assert_eq!(restored.bytes(), b"old valid bytes");
    // NEGATIVE PROOF: publisher identity / external monotonic witness absent.
}
