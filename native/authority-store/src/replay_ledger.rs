//! Offline, non-authorizing SQLite replay ledger feasibility.
//! A trusted broker must supply a verified OS-owned SQLite connection, binding
//! the epoch, database file and independent policy witness before any grant.
use crate::StoreDenied;
#[cfg(test)]
use rusqlite::OpenFlags;
use rusqlite::MAIN_DB;
use rusqlite::{params, Connection, TransactionBehavior};
#[cfg(any(test, all(feature = "offline-fixture", debug_assertions)))]
use std::time::Duration;

const MAX_CLAIMS_PER_EPOCH: i64 = 1024;
const REPLAY_SCHEMA: &str = "CREATE TABLE replay_claims (epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)=16), PRIMARY KEY(epoch,request)) WITHOUT ROWID";

/// A private-issuer durable replay primitive, NOT an authority to perform I/O.
/// There is deliberately no public production connection/path constructor.
/// The fixture API exists only in explicitly opted-in debug builds.
/// Compile-fail coverage is conditional: with the test feature enabled, the
/// fixture intentionally exists, and its test must not claim otherwise.
#[cfg_attr(
    not(feature = "offline-fixture"),
    doc = r#"
```compile_fail
use jdc_authority_store::replay_ledger::ReplayClaimLedger;
use rusqlite::Connection;
let untrusted = Connection::open_in_memory().unwrap();
let _ = ReplayClaimLedger::from_offline_fixture(untrusted, 7);
```
"#
)]
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
    #[cfg(any(test, all(feature = "offline-fixture", debug_assertions)))]
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

    /// OFFLINE TEST FIXTURE ONLY. Compiled only for explicitly opted-in
    /// development builds with debug assertions. Never an OS-attested store:
    /// arbitrary Connection values cannot prove file identity or rollback
    /// resistance. No production issuer may call this function.
    #[cfg(all(feature = "offline-fixture", debug_assertions))]
    pub fn from_offline_fixture(db: Connection, epoch: u64) -> Result<Self, StoreDenied> {
        Self::from_existing_connection(db, epoch)
    }

    /// Read-only verification of an already OS-read, bounded SQLite image.
    /// DATA ONLY: neither custody, replay freshness nor permission to mutate
    /// follows from these bytes. Never reopen the source filename.
    /// Preserve bounded historical claims across policy epochs, while
    /// limiting both retained generations and claims within each generation.
    /// Never evict previously consumed IDs during observation.
    pub fn inspect_serialized_snapshot(raw: &[u8], epoch: u64) -> Result<u32, StoreDenied> {
        const MAX_IMAGE: usize = 16 * 1024 * 1024;
        const MAX_GENERATIONS: usize = 16;
        const MAX_TOTAL: u32 = MAX_CLAIMS_PER_EPOCH as u32 * MAX_GENERATIONS as u32;
        if epoch == 0
            || raw.len() < 512
            || raw.len() > MAX_IMAGE
            || !raw.len().is_multiple_of(512)
            || raw.get(..16) != Some(b"SQLite format 3\0")
            || raw[18] != 1
            || raw[19] != 1
        {
            return Err(StoreDenied);
        }
        let mut db = Connection::open_in_memory().map_err(|_| StoreDenied)?;
        db.deserialize_read_exact(MAIN_DB, std::io::Cursor::new(raw), raw.len(), true)
            .map_err(|_| StoreDenied)?;
        db.pragma_update(None, "query_only", 1)
            .map_err(|_| StoreDenied)?;
        let read_only: i64 = db
            .pragma_query_value(None, "query_only", |r| r.get(0))
            .map_err(|_| StoreDenied)?;
        if read_only != 1 {
            return Err(StoreDenied);
        }
        verify_schema(&db)?;
        let integrity: String = db
            .query_row("PRAGMA quick_check(1)", [], |r| r.get(0))
            .map_err(|_| StoreDenied)?;
        if integrity != "ok" {
            return Err(StoreDenied);
        }
        let mut statement = db
            .prepare(
                "SELECT typeof(epoch),length(epoch),substr(epoch,1,9),
                    typeof(request),length(request),substr(request,1,17)
             FROM replay_claims LIMIT 16385",
            )
            .map_err(|_| StoreDenied)?;
        let mut rows = statement.query([]).map_err(|_| StoreDenied)?;
        let mut count: u32 = 0;
        let mut generations = std::collections::BTreeMap::<u64, u32>::new();
        while let Some(row) = rows.next().map_err(|_| StoreDenied)? {
            if count >= MAX_TOTAL {
                return Err(StoreDenied);
            }
            let kind_epoch: String = row.get(0).map_err(|_| StoreDenied)?;
            let epoch_len: i64 = row.get(1).map_err(|_| StoreDenied)?;
            let epoch_blob: Vec<u8> = row.get(2).map_err(|_| StoreDenied)?;
            let kind_request: String = row.get(3).map_err(|_| StoreDenied)?;
            let request_len: i64 = row.get(4).map_err(|_| StoreDenied)?;
            let request_blob: Vec<u8> = row.get(5).map_err(|_| StoreDenied)?;
            if kind_epoch != "blob"
                || epoch_len != 8
                || epoch_blob.len() != 8
                || kind_request != "blob"
                || request_len != 16
                || request_blob.len() != 16
            {
                return Err(StoreDenied);
            }
            let existing_epoch =
                u64::from_be_bytes(epoch_blob.try_into().map_err(|_| StoreDenied)?);
            if existing_epoch == 0
                || existing_epoch > epoch
                || request_blob[6] >> 4 != 4
                || request_blob[8] & 0b1100_0000 != 0b1000_0000
            {
                return Err(StoreDenied);
            }
            let per_generation = generations.entry(existing_epoch).or_default();
            *per_generation += 1;
            if *per_generation > MAX_CLAIMS_PER_EPOCH as u32 || generations.len() > MAX_GENERATIONS
            {
                return Err(StoreDenied);
            }
            count += 1;
        }
        Ok(count)
    }

    /// Return the immutable epoch captured when this ledger was opened.
    /// This is identity metadata only, never proof of OS storage custody.
    pub fn bound_epoch(&self) -> u64 {
        self.expected_epoch
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
    fn read_only_serialized_replay_snapshot_checks_actual_rows_and_epoch() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        open(&path, 7).claim_once(canonical_id(0x12)).unwrap();
        let image = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let count = ReplayClaimLedger::inspect_serialized_snapshot(&image, 7).unwrap();
        assert_eq!(count, 1);
        assert!(ReplayClaimLedger::inspect_serialized_snapshot(&image, 0).is_err());
        assert!(ReplayClaimLedger::inspect_serialized_snapshot(&image, 6).is_err());
        assert!(ReplayClaimLedger::inspect_serialized_snapshot(&image[..32], 7).is_err());
        let mut changed = image.clone();
        changed[18] = 2; // WAL write-version needs a recovery VFS, not raw pages
        assert!(ReplayClaimLedger::inspect_serialized_snapshot(&changed, 7).is_err());
    }

    #[test]
    fn serialized_snapshot_retains_bounded_claims_across_policy_epochs() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let mut db = Connection::open(&path).unwrap();
        let tx = db.transaction().unwrap();
        for (epoch, count) in [(7u64, 600u32), (8u64, 500u32)] {
            for n in 0..count {
                let mut id = [0u8; 16];
                id[0..4].copy_from_slice(&n.to_be_bytes());
                id[6] = 0x40;
                id[8] = 0x80;
                tx.execute(
                    "INSERT INTO replay_claims(epoch,request) VALUES (?1,?2)",
                    params![epoch.to_be_bytes().as_slice(), id.as_slice()],
                )
                .unwrap();
            }
        }
        tx.commit().unwrap();
        drop(db);
        assert_eq!(
            ReplayClaimLedger::inspect_serialized_snapshot(&std::fs::read(path).unwrap(), 8),
            Ok(1100)
        );
    }

    #[test]
    fn serialized_replay_snapshot_rejects_untrusted_row_and_extra_schema() {
        let f = tempdir().unwrap();
        let path = f.path().join("claims.sqlite3");
        setup(&path);
        let db = Connection::open(&path).unwrap();
        let epoch = 7u64.to_be_bytes();
        db.execute(
            "INSERT INTO replay_claims(epoch,request) VALUES (?1,?2)",
            params![epoch.as_slice(), [0x11u8; 16].as_slice()],
        )
        .unwrap();
        drop(db);
        assert!(
            ReplayClaimLedger::inspect_serialized_snapshot(&std::fs::read(&path).unwrap(), 7)
                .is_err(),
            "invalid UUID version/variant must deny even if SQLite constraints pass"
        );
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE injected (x TEXT)").unwrap();
        drop(db);
        assert!(
            ReplayClaimLedger::inspect_serialized_snapshot(&std::fs::read(&path).unwrap(), 7)
                .is_err(),
            "additional schema objects must deny"
        );
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
