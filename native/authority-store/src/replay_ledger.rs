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
/// let _ledger = ReplayClaimLedger::from_existing_connection(forged);
/// ```
pub struct ReplayClaimLedger {
    connection: Connection,
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
    fn from_existing_connection(db: Connection) -> Result<Self, StoreDenied> {
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
        Ok(Self { connection: db })
    }

    /// Claims exactly one request within one epoch, atomically. Failures are
    /// DENIALS, including after-commit uncertainty; do not retry automatically.
    /// The ID must come from the independently validated canonical wire frame.
    pub fn claim_once(&mut self, epoch: u64, request_id: [u8; 16]) -> Result<(), StoreDenied> {
        if epoch == 0 {
            return Err(StoreDenied);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreDenied)?;
        verify_schema(&tx)?;
        let epoch = epoch.to_be_bytes();
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
    fn setup(path: &Path) {
        let db = Connection::open(path).unwrap();
        db.execute_batch("PRAGMA application_id=0x4A44434C; PRAGMA user_version=1;")
            .unwrap();
        db.execute_batch(SCHEMA_FIXTURE).unwrap();
    }
    fn open(path: &Path) -> ReplayClaimLedger {
        let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
        ReplayClaimLedger::from_existing_connection(db).unwrap()
    }
    #[test]
    fn committed_claim_survives_close_and_denies_replay_after_restart() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let id = [0x42; 16];
        open(&path).claim_once(7, id).unwrap();
        assert!(open(&path).claim_once(7, id).is_err());
        open(&path).claim_once(8, id).unwrap();
        assert!(open(&path).claim_once(0, [0x43; 16]).is_err());
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
                        let mut ledger = open(&file);
                        gate.wait();
                        ledger.claim_once(7, [0x12; 16]).is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|&&won| won).count(), 1);
        assert!(open(&path).claim_once(7, [0x12; 16]).is_err());
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
        assert!(ReplayClaimLedger::from_existing_connection(db).is_err());
    }
    #[test]
    fn schema_mutation_between_claims_denies_before_mutation() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let mut ledger = open(&path);
        ledger.claim_once(3, [0x11; 16]).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE injected (id INTEGER);")
            .unwrap();
        assert!(ledger.claim_once(3, [0x22; 16]).is_err());
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
        open(&path).claim_once(3, [0x11; 16]).unwrap();
        std::fs::copy(&path, &old).unwrap();
        open(&path).claim_once(3, [0x22; 16]).unwrap();
        std::fs::copy(&old, &path).unwrap();
        assert!(
            open(&path).claim_once(3, [0x22; 16]).is_ok(),
            "NEGATIVE PROOF: untrusted whole-file SQLite rollback revives an ID"
        );
    }
    #[test]
    fn claim_limit_never_evicts_a_consumed_request() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let mut ledger = open(&path);
        for n in 0..1024u32 {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&n.to_be_bytes());
            ledger.claim_once(12, id).unwrap();
        }
        assert!(ledger.claim_once(12, [0xff; 16]).is_err());
        drop(ledger);
        assert!(open(&path).claim_once(12, [0; 16]).is_err());
    }
}
