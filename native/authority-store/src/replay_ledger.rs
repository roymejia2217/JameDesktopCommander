//! Offline, non-authorizing SQLite replay ledger feasibility.
//! A trusted broker must supply a verified OS-owned SQLite connection, binding
//! the epoch, database file and independent policy witness before any grant.
use crate::StoreDenied;
use rusqlite::{params, Connection, TransactionBehavior};
#[cfg(test)]
use rusqlite::{OpenFlags, MAIN_DB};
#[cfg(test)]
use std::time::Duration;

const MAX_CLAIMS_PER_EPOCH: i64 = 1024;
const REPLAY_SCHEMA: &str = "CREATE TABLE replay_claims (epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)=16), PRIMARY KEY(epoch,request)) WITHOUT ROWID";

/// A private-issuer durable replay primitive, NOT an authority to perform I/O.
/// There is deliberately no public connection/path constructor.
/// ```compile_fail
/// use jdc_authority_store::replay_ledger::ReplayClaimLedger;
/// use rusqlite::Connection;
/// let forged = Connection::open_in_memory().unwrap();
/// let _ledger = ReplayClaimLedger::from_existing_connection(forged, 7);
/// ```
/// The client also cannot change the epoch on an individual claim:
/// ```compile_fail
/// use jdc_authority_store::replay_ledger::ReplayClaimLedger;
/// fn bypass(mut ledger: ReplayClaimLedger) {
///     ledger.claim_once(99, [0x11; 16]);
/// }
/// ```
pub struct ReplayClaimLedger {
    connection: Connection,
    expected_epoch: u64,
}
fn verify_schema(db: &Connection) -> Result<(), StoreDenied> {
    let app: i64 = db
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(|_| StoreDenied)?;
    let version: i64 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|_| StoreDenied)?;
    if app != 0x4A44434C || version != 1 {
        return Err(StoreDenied);
    }
    let (kind, sql): (String, String) = db
        .query_row(
            "SELECT type, sql FROM sqlite_schema WHERE name='replay_claims'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| StoreDenied)?;
    let objects: i64 = db
        .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |r| r.get(0))
        .map_err(|_| StoreDenied)?;
    if objects != 1 || kind != "table" || sql != REPLAY_SCHEMA {
        return Err(StoreDenied);
    }
    Ok(())
}
impl ReplayClaimLedger {
    // Only usable inside this crate's isolated offline fixture. Future service
    // construction requires an independently reviewed OS-descriptor-bound VFS.
    #[cfg(test)]
    fn from_existing_connection(db: Connection, expected_epoch: u64) -> Result<Self, StoreDenied> {
        if expected_epoch == 0 {
            return Err(StoreDenied);
        }
        if db.is_readonly(MAIN_DB).map_err(|_| StoreDenied)? {
            return Err(StoreDenied);
        }
        db.busy_timeout(Duration::from_secs(3))
            .map_err(|_| StoreDenied)?;
        let mode: String = db
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .map_err(|_| StoreDenied)?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(StoreDenied);
        }
        db.pragma_update(None, "synchronous", "EXTRA")
            .map_err(|_| StoreDenied)?;
        let sync: i64 = db
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .map_err(|_| StoreDenied)?;
        if sync != 3 {
            return Err(StoreDenied);
        }
        verify_schema(&db)?;
        Ok(Self {
            connection: db,
            expected_epoch,
        })
    }

    /// Claims exactly one request in the epoch pinned at construction.
    /// Failures are DENIALS, including after-commit uncertainty; do not retry.
    /// The ID must come from the independently validated canonical wire frame.
    /// A future issuer must bind this immutable epoch to the trusted witness.
    pub fn claim_once(&mut self, request_id: [u8; 16]) -> Result<(), StoreDenied> {
        // Enforce the C4d UUIDv4 version/variant at the last persistence boundary.
        // Raw bytes from untrusted callers must not consume durable replay slots.
        if request_id[6] >> 4 != 4 || request_id[8] & 0b1100_0000 != 0b1000_0000 {
            return Err(StoreDenied);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreDenied)?;
        verify_schema(&tx)?;
        let epoch = self.expected_epoch.to_be_bytes();
        let existing: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM replay_claims WHERE epoch=?1",
                params![epoch.as_slice()],
                |r| r.get(0),
            )
            .map_err(|_| StoreDenied)?;
        if existing >= MAX_CLAIMS_PER_EPOCH {
            return Err(StoreDenied);
        }
        if tx
            .execute(
                "INSERT INTO replay_claims (epoch,request) VALUES (?1,?2)",
                params![epoch.as_slice(), request_id.as_slice()],
            )
            .map_err(|_| StoreDenied)?
            != 1
        {
            return Err(StoreDenied);
        }
        tx.commit().map_err(|_| StoreDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::Path,
        sync::{Arc, Barrier},
    };
    use tempfile::tempdir;

    const SCHEMA_FIXTURE: &str = "CREATE TABLE replay_claims (epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)=16), PRIMARY KEY(epoch,request)) WITHOUT ROWID";
    fn canonical_id(marker: u8) -> [u8; 16] {
        let mut id = [marker; 16];
        id[6] = 0x40;
        id[8] = 0x80;
        id
    }
    fn setup(path: &Path) {
        let db = Connection::open(path).unwrap();
        db.execute_batch("PRAGMA application_id=0x4A44434C; PRAGMA user_version=1;")
            .unwrap();
        db.execute_batch(SCHEMA_FIXTURE).unwrap();
    }
    fn open(path: &Path, expected_epoch: u64) -> ReplayClaimLedger {
        let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
        ReplayClaimLedger::from_existing_connection(db, expected_epoch).unwrap()
    }
    #[test]
    fn committed_claim_survives_close_and_denies_replay_after_restart() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let id = canonical_id(0x42);
        open(&path, 7).claim_once(id).unwrap();
        assert!(open(&path, 7).claim_once(id).is_err());
        open(&path, 8).claim_once(id).unwrap();
        let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
        assert!(ReplayClaimLedger::from_existing_connection(db, 0).is_err());
    }
    #[test]
    fn each_claim_uses_the_constructor_bound_epoch_not_an_input_epoch() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let mut epoch_seven = open(&path, 7);
        epoch_seven.claim_once(canonical_id(0x33)).unwrap();
        epoch_seven.claim_once(canonical_id(0x44)).unwrap();
        assert!(open(&path, 7).claim_once(canonical_id(0x33)).is_err());
        let db = Connection::open(&path).unwrap();
        let stored_epoch: Vec<u8> = db
            .query_row("SELECT DISTINCT epoch FROM replay_claims", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(stored_epoch, 7u64.to_be_bytes());
        // A future trusted updater must explicitly issue a new pinned ledger.
        open(&path, 8).claim_once(canonical_id(0x33)).unwrap();
        assert!(epoch_seven.claim_once(canonical_id(0x33)).is_err());
    }
    #[test]
    fn rejects_non_uuidv4_ids_before_persistent_replay_claims() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let mut ledger = open(&path, 7);
        let mut bad_version = canonical_id(0x25);
        bad_version[6] = 0x50; // valid variant, invalid version 5
        let mut bad_variant = canonical_id(0x26);
        bad_variant[8] = 0xc0; // valid version 4, invalid RFC variant
        for invalid in [[0; 16], [0xff; 16], bad_version, bad_variant] {
            assert!(
                ledger.claim_once(invalid).is_err(),
                "non UUIDv4 replay ID must DENY"
            );
        }
        let db = Connection::open(&path).unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM replay_claims", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "denied IDs must not consume the ledger");
    }
    #[test]
    fn two_independent_connections_cannot_both_claim_same_request() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let barrier = Arc::new(Barrier::new(2));
        let results = std::thread::scope(|s| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let gate = Arc::clone(&barrier);
                    let file = path.clone();
                    s.spawn(move || {
                        let mut ledger = open(&file, 7);
                        gate.wait();
                        ledger.claim_once(canonical_id(0x12)).is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|&&won| won).count(), 1);
        assert!(open(&path, 7).claim_once(canonical_id(0x12)).is_err());
    }
    #[test]
    fn schema_tampering_and_unprovisioned_files_fail_closed() {
        let f = tempdir().unwrap();
        let missing = f.path().join("missing.sqlite3");
        assert!(Connection::open_with_flags(&missing, OpenFlags::SQLITE_OPEN_READ_WRITE).is_err());
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE foreign_table (value TEXT);")
            .unwrap();
        assert!(ReplayClaimLedger::from_existing_connection(db, 7).is_err());
    }
    #[test]
    fn schema_mutation_between_claims_denies_before_mutation() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let mut ledger = open(&path, 3);
        ledger.claim_once(canonical_id(0x11)).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE injected (id INTEGER);")
            .unwrap();
        assert!(ledger.claim_once(canonical_id(0x22)).is_err());
        let db = Connection::open(&path).unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM replay_claims", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "rejected claim must not mutate ledger");
    }
    #[test]
    fn offline_file_rollback_still_reopens_a_consumed_request_negative_proof() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        let old = f.path().join("old.sqlite3");
        setup(&path);
        open(&path, 3).claim_once(canonical_id(0x11)).unwrap();
        std::fs::copy(&path, &old).unwrap();
        open(&path, 3).claim_once(canonical_id(0x22)).unwrap();
        std::fs::copy(&old, &path).unwrap();
        assert!(
            open(&path, 3).claim_once(canonical_id(0x22)).is_ok(),
            "NEGATIVE PROOF: untrusted whole-file SQLite rollback revives an ID"
        );
    }
    #[test]
    fn claim_limit_never_evicts_a_consumed_request() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let mut ledger = open(&path, 12);
        for n in 0..1024u32 {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&n.to_be_bytes());
            id[6] = 0x40;
            id[8] = 0x80;
            ledger.claim_once(id).unwrap();
        }
        assert!(ledger.claim_once(canonical_id(0xff)).is_err());
        drop(ledger);
        assert!(open(&path, 12).claim_once(canonical_id(0)).is_err());
    }
}
