//! Isolated SQLite v2 exact-byte policy storage feasibility slice.
//! This module is NOT a trusted policy publisher, issuer, service root, or grant.
//! The supplied database pathname is untrusted and whole-image rollback remains possible.
use crate::StoreDenied;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior, MAIN_DB};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

const MAX_POLICY_BYTES: usize = 65_536;
const SCHEMA_V2: &str =
    "CREATE TABLE protected_policy (slot INTEGER PRIMARY KEY CHECK(slot=1), epoch BLOB NOT NULL CHECK(length(epoch)=8), digest BLOB NOT NULL CHECK(length(digest)=32), policy_bytes BLOB NOT NULL CHECK(typeof(policy_bytes)='blob' AND length(policy_bytes)<=65536))";

/// Owned result proves only internal SHA-256 consistency, not publisher authority.
pub struct VerifiedPolicy {
    epoch: u64,
    digest: [u8; 32],
    bytes: Vec<u8>,
}
impl VerifiedPolicy {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Offline experiment; intentionally impossible to instantiate from MCP.
pub struct PolicyBytesStore {
    connection: Connection,
}
fn check_schema(db: &Connection) -> Result<(), StoreDenied> {
    let app: i64 = db
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(|_| StoreDenied)?;
    let version: i64 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|_| StoreDenied)?;
    if app != 0x4A444332 || version != 2 {
        return Err(StoreDenied);
    }
    let unexpected: i64 = db.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type <> 'table' OR name <> 'protected_policy'",
        [], |r| r.get(0),
    ).map_err(|_| StoreDenied)?;
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM protected_policy", [], |r| r.get(0))
        .map_err(|_| StoreDenied)?;
    if unexpected != 0 || count != 1 {
        return Err(StoreDenied);
    }
    let definition: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='protected_policy'",
            [],
            |r| r.get(0),
        )
        .map_err(|_| StoreDenied)?;
    if definition != SCHEMA_V2 {
        return Err(StoreDenied);
    }
    Ok(())
}

// SQL computes full sizes but returns bounded prefixes, never untrusted full-size blobs.
fn current(db: &Connection) -> Result<VerifiedPolicy, StoreDenied> {
    type Raw = (
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
    let (ek, el, e, dk, dl, d, bk, bl, b): Raw = db.query_row(
        "SELECT typeof(epoch),length(epoch),substr(epoch,1,9), typeof(digest),length(digest),substr(digest,1,33), typeof(policy_bytes),length(policy_bytes),CASE WHEN length(policy_bytes)=0 THEN x'' ELSE substr(policy_bytes,1,65537) END FROM protected_policy WHERE slot=1",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)),
    ).map_err(|_| StoreDenied)?;
    if ek != "blob"
        || dk != "blob"
        || bk != "blob"
        || el != 8
        || dl != 32
        || !(0..=MAX_POLICY_BYTES as i64).contains(&bl)
        || b.len() != bl as usize
    {
        return Err(StoreDenied);
    }
    let epoch = u64::from_be_bytes(e.try_into().map_err(|_| StoreDenied)?);
    let digest: [u8; 32] = d.try_into().map_err(|_| StoreDenied)?;
    let valid = if epoch == 0 {
        b.is_empty() && digest == [0; 32]
    } else {
        !b.is_empty() && digest != [0; 32] && digest == PolicyBytesStore::digest_exact(&b)
    };
    if !valid {
        return Err(StoreDenied);
    }
    Ok(VerifiedPolicy {
        epoch,
        digest,
        bytes: b,
    })
}
impl PolicyBytesStore {
    pub fn digest_exact(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// No schema auto-create/migration and no implicit rollback recovery.
    /// This pathname method is for isolated feasibility tests, not production custody.
    pub fn open_existing(path: &Path) -> Result<Self, StoreDenied> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| StoreDenied)?;
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
        check_schema(&db)?;
        current(&db)?;
        Ok(Self { connection: db })
    }

    pub fn read_verified(&self) -> Result<VerifiedPolicy, StoreDenied> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(|_| StoreDenied)?;
        check_schema(&tx)?;
        let record = current(&tx)?;
        tx.commit().map_err(|_| StoreDenied)?;
        if record.epoch == 0 {
            return Err(StoreDenied);
        }
        Ok(record)
    }

    /// Compare with a separately trusted epoch+digest witness. This is
    /// only a byte-for-byte matching primitive: the caller MUST acquire its
    /// witness independently through a protected OS policy authority, NEVER
    /// from MCP request data or from this same SQLite database.
    pub fn read_matching_witness(
        &self,
        expected_epoch: u64,
        expected_digest: &[u8; 32],
    ) -> Result<VerifiedPolicy, StoreDenied> {
        if expected_epoch == 0 || *expected_digest == [0; 32] {
            return Err(StoreDenied);
        }
        let policy = self.read_verified()?;
        if policy.epoch != expected_epoch || policy.digest != *expected_digest {
            return Err(StoreDenied);
        }
        Ok(policy)
    }

    /// A transaction only, NOT writer authorization or trusted policy approval.
    pub fn commit_after(
        &mut self,
        expected: u64,
        next: u64,
        bytes: &[u8],
    ) -> Result<(), StoreDenied> {
        if next <= expected || bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err(StoreDenied);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreDenied)?;
        check_schema(&tx)?;
        let preceding = current(&tx)?;
        if preceding.epoch != expected {
            return Err(StoreDenied);
        }
        let digest = Self::digest_exact(bytes);
        let updated = tx.execute(
            "UPDATE protected_policy SET epoch=?1,digest=?2,policy_bytes=?3 WHERE slot=1 AND epoch=?4",
            params![next.to_be_bytes().as_slice(),digest.as_slice(),bytes,expected.to_be_bytes().as_slice()],
        ).map_err(|_| StoreDenied)?;
        if updated != 1 {
            return Err(StoreDenied);
        }
        tx.commit().map_err(|_| StoreDenied)
    }
}
