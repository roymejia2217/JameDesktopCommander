//! T011-C4 test-only proof of a coherent policy + replay SQLite transaction.
//! Neither the witness argument nor the SQLite path is authenticated here.
//! In production this must stay unavailable until an OS-owned issuer and
//! descriptor/sidecar custody are independently established.
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior, MAIN_DB};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

const POLICY_SQL: &str = "CREATE TABLE protected_policy (slot INTEGER PRIMARY KEY CHECK(slot=1), epoch BLOB NOT NULL CHECK(length(epoch)=8), digest BLOB NOT NULL CHECK(length(digest)=32), policy_bytes BLOB NOT NULL CHECK(typeof(policy_bytes)='blob' AND length(policy_bytes)<=65536))";
const REPLAY_SQL: &str = "CREATE TABLE replay_claims (epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)=16), PRIMARY KEY(epoch,request)) WITHOUT ROWID";
const APP_ID: i64 = 0x4A444333;
const CAP: i64 = 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refused;

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn valid_uuid_v4(id: [u8; 16]) -> bool {
    id[6] >> 4 == 4 && id[8] & 0xc0 == 0x80
}
fn schema(db: &Connection) -> Result<(), Refused> {
    let app: i64 = db
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(|_| Refused)?;
    let ver: i64 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|_| Refused)?;
    if app != APP_ID || ver != 3 {
        return Err(Refused);
    }
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |r| r.get(0))
        .map_err(|_| Refused)?;
    if count != 2 {
        return Err(Refused);
    }
    for (name, expected) in [
        ("protected_policy", POLICY_SQL),
        ("replay_claims", REPLAY_SQL),
    ] {
        let (kind, sql): (String, String) = db
            .query_row(
                "SELECT type,sql FROM sqlite_schema WHERE name=?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| Refused)?;
        if kind != "table" || sql != expected {
            return Err(Refused);
        }
    }
    Ok(())
}
fn policy_matches(db: &Connection, epoch: u64, digest: &[u8; 32]) -> Result<(), Refused> {
    // Never materialize full untrusted SQLite BLOBs without bounds.
    type Row = (
        String,
        i64,
        Vec<u8>,
        String,
        i64,
        Vec<u8>,
        String,
        i64,
        Vec<u8>,
    );
    let row: Row = db.query_row(
        "SELECT typeof(epoch),length(epoch),substr(epoch,1,9),typeof(digest),length(digest),substr(digest,1,33),typeof(policy_bytes),length(policy_bytes),CASE WHEN length(policy_bytes)=0 THEN x'' ELSE substr(policy_bytes,1,65537) END FROM protected_policy WHERE slot=1",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)),
    ).map_err(|_| Refused)?;
    let (et, el, eb, dt, dl, digest_bytes, pt, pl, pb) = row;
    if epoch == 0
        || *digest == [0; 32]
        || et != "blob"
        || el != 8
        || eb.len() != 8
        || dt != "blob"
        || dl != 32
        || digest_bytes.len() != 32
        || pt != "blob"
        || !(1..=65536).contains(&pl)
        || pb.len() != pl as usize
    {
        return Err(Refused);
    }
    if eb != epoch.to_be_bytes() || digest_bytes != digest.as_slice() || hash(&pb) != *digest {
        return Err(Refused);
    }
    let count: i64 = db_query_count(db)?;
    if count != 1 {
        return Err(Refused);
    }
    Ok(())
}
fn db_query_count(db: &Connection) -> Result<i64, Refused> {
    db.query_row("SELECT COUNT(*) FROM protected_policy", [], |r| r.get(0))
        .map_err(|_| Refused)
}
struct CoherentProof {
    db: Connection,
}
impl CoherentProof {
    fn from_preprovisioned(db: Connection) -> Result<Self, Refused> {
        if db.is_readonly(MAIN_DB).map_err(|_| Refused)? {
            return Err(Refused);
        }
        db.busy_timeout(Duration::from_secs(3))
            .map_err(|_| Refused)?;
        let mode: String = db
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .map_err(|_| Refused)?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(Refused);
        }
        db.pragma_update(None, "synchronous", "EXTRA")
            .map_err(|_| Refused)?;
        let sync: i64 = db
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .map_err(|_| Refused)?;
        if sync != 3 {
            return Err(Refused);
        }
        schema(&db)?;
        Ok(Self { db })
    }
    fn claim_if_witness_matches(
        &mut self,
        epoch: u64,
        digest: [u8; 32],
        id: [u8; 16],
    ) -> Result<(), Refused> {
        if !valid_uuid_v4(id) {
            return Err(Refused);
        }
        // Policy, schema, quota and replay claim MUST be one IMMEDIATE txn.
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Refused)?;
        schema(&tx)?;
        policy_matches(&tx, epoch, &digest)?;
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM replay_claims WHERE epoch=?1",
                params![epoch.to_be_bytes().as_slice()],
                |r| r.get(0),
            )
            .map_err(|_| Refused)?;
        if count >= CAP {
            return Err(Refused);
        }
        if tx
            .execute(
                "INSERT INTO replay_claims (epoch,request) VALUES (?1,?2)",
                params![epoch.to_be_bytes().as_slice(), id.as_slice()],
            )
            .map_err(|_| Refused)?
            != 1
        {
            return Err(Refused);
        }
        tx.commit().map_err(|_| Refused)
    }
}

// An administrator fixture can mutate state in tests, but the runtime
// library intentionally has NO equivalent issuer or public constructor.
fn provision(path: &Path, epoch: u64, policy: &[u8]) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("PRAGMA application_id=0x4A444333; PRAGMA user_version=3;")
        .unwrap();
    db.execute_batch(POLICY_SQL).unwrap();
    db.execute_batch(REPLAY_SQL).unwrap();
    db.execute(
        "INSERT INTO protected_policy (slot,epoch,digest,policy_bytes) VALUES (1,?1,?2,?3)",
        params![
            epoch.to_be_bytes().as_slice(),
            hash(policy).as_slice(),
            policy
        ],
    )
    .unwrap();
}
fn open(path: &Path) -> CoherentProof {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
    CoherentProof::from_preprovisioned(db).unwrap()
}
fn id(marker: u8) -> [u8; 16] {
    let mut bytes = [marker; 16];
    bytes[6] = 0x40;
    bytes[8] = 0x80;
    bytes
}

#[test]
fn coherent_policy_and_replay_claim_share_one_sqlite_transaction() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("combined.sqlite3");
    provision(&path, 7, b"policy-seven");
    let mut store = open(&path);
    let witness = hash(b"policy-seven");
    assert_eq!(store.claim_if_witness_matches(7, witness, id(1)), Ok(()));
    assert_eq!(
        store.claim_if_witness_matches(7, witness, id(1)),
        Err(Refused)
    );
    assert_eq!(
        store.claim_if_witness_matches(7, [0x22; 32], id(2)),
        Err(Refused)
    );
    assert_eq!(
        store.claim_if_witness_matches(6, witness, id(2)),
        Err(Refused)
    );
    assert_eq!(
        store.claim_if_witness_matches(7, witness, [0; 16]),
        Err(Refused)
    );
    let (epoch, total): (Vec<u8>, i64) = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT epoch, (SELECT COUNT(*) FROM replay_claims) FROM protected_policy",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(epoch, 7u64.to_be_bytes());
    assert_eq!(total, 1);
}
#[test]
fn administrative_epoch_change_invalidates_old_claims_before_replay_insert() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("combined.sqlite3");
    provision(&path, 7, b"policy-seven");
    let mut store = open(&path);
    store
        .claim_if_witness_matches(7, hash(b"policy-seven"), id(1))
        .unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE protected_policy SET epoch=?1,digest=?2,policy_bytes=?3 WHERE slot=1",
        params![
            8u64.to_be_bytes().as_slice(),
            hash(b"policy-eight").as_slice(),
            b"policy-eight"
        ],
    )
    .unwrap();
    assert_eq!(
        store.claim_if_witness_matches(7, hash(b"policy-seven"), id(2)),
        Err(Refused)
    );
    assert_eq!(
        store.claim_if_witness_matches(8, hash(b"policy-eight"), id(2)),
        Ok(())
    );
    assert_eq!(
        store.claim_if_witness_matches(8, hash(b"policy-seven"), id(3)),
        Err(Refused)
    );
}
#[test]
fn independent_concurrent_connections_have_exactly_one_claim_winner() {
    use std::sync::{Arc, Barrier};
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("combined.sqlite3");
    provision(&path, 7, b"policy-seven");
    let gate = Arc::new(Barrier::new(2));
    let winners = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let gate = Arc::clone(&gate);
                scope.spawn(move || {
                    let mut store = open(&path);
                    gate.wait();
                    store
                        .claim_if_witness_matches(7, hash(b"policy-seven"), id(4))
                        .is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(winners.iter().filter(|&&yes| yes).count(), 1);
    assert_eq!(
        open(&path).claim_if_witness_matches(7, hash(b"policy-seven"), id(4)),
        Err(Refused)
    );
}
#[test]
fn schema_mutation_does_not_commit_claim() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("combined.sqlite3");
    provision(&path, 7, b"policy-seven");
    let mut store = open(&path);
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE extra (id INTEGER)")
        .unwrap();
    assert_eq!(
        store.claim_if_witness_matches(7, hash(b"policy-seven"), id(5)),
        Err(Refused)
    );
    let count: i64 = Connection::open(&path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM replay_claims", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}
#[test]
fn restoring_old_complete_database_still_defeats_local_replay_guarantee() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("combined.sqlite3");
    let backup = tmp.path().join("snapshot.sqlite3");
    provision(&path, 7, b"policy-seven");
    std::fs::copy(&path, &backup).unwrap();
    open(&path)
        .claim_if_witness_matches(7, hash(b"policy-seven"), id(6))
        .unwrap();
    std::fs::copy(&backup, &path).unwrap();
    // Intentionally NEGATIVE: without independent OS-backed monotonic
    // witness, a whole-image rollback resurrects a consumed UUID.
    assert_eq!(
        open(&path).claim_if_witness_matches(7, hash(b"policy-seven"), id(6)),
        Ok(())
    );
}
