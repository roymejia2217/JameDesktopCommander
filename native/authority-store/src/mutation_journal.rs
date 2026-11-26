//! Nonshipping v2 transaction engine for one independently admitted domain.
//! This is not authorization or a protected VFS. The existing pathname-based
//! SQLite custody restrictions still apply to the database and its journal.
//! Never migrate, provision or reconcile unknown outcomes automatically.
use crate::StoreDenied;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::{path::Path, time::Duration};

const SCHEMA: &str = "CREATE TABLE protected_state (slot INTEGER PRIMARY KEY CHECK(slot=1), domain BLOB NOT NULL CHECK(typeof(domain)='blob' AND length(domain)=32), epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32), sequence BLOB NOT NULL CHECK(typeof(sequence)='blob' AND length(sequence)=8), phase INTEGER NOT NULL CHECK(phase IN (0,1,2,3)), operation_epoch BLOB NOT NULL CHECK(typeof(operation_epoch)='blob' AND length(operation_epoch)=8), request_digest BLOB NOT NULL CHECK(typeof(request_digest)='blob' AND length(request_digest)=32))";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Phase {
    Initial,
    Pending,
    Committed,
    Rejected,
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Outcome {
    Committed,
    Rejected,
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Snapshot {
    pub epoch: u64,
    pub digest: [u8; 32],
    pub sequence: u64,
    /// Epoch of the last operation, not the current policy epoch.
    pub operation_epoch: u64,
    pub request_digest: [u8; 32],
    pub phase: Phase,
}
pub struct Journal {
    conn: Connection,
    domain: [u8; 32],
}

fn snapshot(conn: &Connection, domain: &[u8; 32]) -> Result<Snapshot, StoreDenied> {
    let (bound, epoch, digest, sequence, phase, operation_epoch, request_digest) = conn
        .query_row(
            "SELECT domain,epoch,digest,sequence,phase,operation_epoch,request_digest FROM protected_state WHERE slot=1",
            [],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, Vec<u8>>(3)?, r.get::<_, i64>(4)?, r.get::<_, Vec<u8>>(5)?, r.get::<_, Vec<u8>>(6)?)),
        )
        .map_err(|_| StoreDenied)?;
    if bound.as_slice() != domain || *domain == [0; 32] {
        return Err(StoreDenied);
    }
    let epoch = u64::from_be_bytes(epoch.try_into().map_err(|_| StoreDenied)?);
    let sequence = u64::from_be_bytes(sequence.try_into().map_err(|_| StoreDenied)?);
    let digest = digest.try_into().map_err(|_| StoreDenied)?;
    let operation_epoch = u64::from_be_bytes(operation_epoch.try_into().map_err(|_| StoreDenied)?);
    let request_digest: [u8; 32] = request_digest.try_into().map_err(|_| StoreDenied)?;
    let phase = match phase {
        0 if sequence == 0 => Phase::Initial,
        1 if sequence != 0 => Phase::Pending,
        2 if sequence != 0 => Phase::Committed,
        3 if sequence != 0 => Phase::Rejected,
        _ => return Err(StoreDenied),
    };
    if epoch == 0
        || operation_epoch > epoch
        || (phase == Phase::Initial && (operation_epoch != 0 || request_digest != [0; 32]))
        || (phase != Phase::Initial && (operation_epoch == 0 || request_digest == [0; 32]))
        || (phase == Phase::Pending && operation_epoch != epoch)
    {
        return Err(StoreDenied);
    }
    Ok(Snapshot {
        epoch,
        digest,
        sequence,
        operation_epoch,
        request_digest,
        phase,
    })
}

impl Journal {
    /// Opens an explicitly provisioned, separately protected database.
    /// A caller-supplied domain ID alone is not proof of volume identity.
    pub fn open_existing(path: &Path, domain: [u8; 32]) -> Result<Self, StoreDenied> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| StoreDenied)?;
        conn.busy_timeout(Duration::from_secs(3))
            .map_err(|_| StoreDenied)?;
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .map_err(|_| StoreDenied)?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(StoreDenied);
        }
        conn.pragma_update(None, "synchronous", "EXTRA")
            .map_err(|_| StoreDenied)?;
        let sync: i64 = conn
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .map_err(|_| StoreDenied)?;
        let app: i64 = conn
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(|_| StoreDenied)?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|_| StoreDenied)?;
        if sync != 3 || app != 0x4A444331 || version != 2 {
            return Err(StoreDenied);
        }
        let unexpected:i64=conn.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE type <> 'table' OR name <> 'protected_state'",[],|r|r.get(0)).map_err(|_|StoreDenied)?;
        let schema: String = conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='protected_state'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| StoreDenied)?;
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM protected_state", [], |r| r.get(0))
            .map_err(|_| StoreDenied)?;
        if unexpected != 0 || schema != SCHEMA || rows != 1 {
            return Err(StoreDenied);
        }
        snapshot(&conn, &domain)?;
        Ok(Self { conn, domain })
    }
    pub fn snapshot(&self) -> Result<Snapshot, StoreDenied> {
        snapshot(&self.conn, &self.domain)
    }

    /// Persist intent BEFORE any irreversible native operation. No work
    /// begins while an earlier intent remains unresolved. The trusted issuer
    /// must bind this sequence to the complete request and never renumber a retry.
    pub fn begin(
        &mut self,
        epoch: u64,
        sequence: u64,
        request_digest: [u8; 32],
    ) -> Result<(), StoreDenied> {
        if request_digest == [0; 32] {
            return Err(StoreDenied);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreDenied)?;
        let state = snapshot(&tx, &self.domain)?;
        if state.epoch != epoch
            || state.phase == Phase::Pending
            || state.sequence.checked_add(1) != Some(sequence)
        {
            return Err(StoreDenied);
        }
        let changed = tx
            .execute(
                "UPDATE protected_state SET sequence=?1,phase=1,operation_epoch=?2,request_digest=?3 WHERE slot=1",
                params![sequence.to_be_bytes().as_slice(), epoch.to_be_bytes().as_slice(), request_digest.as_slice()],
            )
            .map_err(|_| StoreDenied)?;
        if changed != 1 {
            return Err(StoreDenied);
        }
        tx.commit().map_err(|_| StoreDenied)
    }

    /// Only a trusted broker/reconciler that knows the native outcome may
    /// finish an intent. A disconnect, timeout or unknown result is NOT
    /// Rejected. A failed transaction is itself uncertain to the caller.
    pub fn finish(
        &mut self,
        epoch: u64,
        sequence: u64,
        request_digest: [u8; 32],
        outcome: Outcome,
    ) -> Result<(), StoreDenied> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreDenied)?;
        let state = snapshot(&tx, &self.domain)?;
        if state.epoch != epoch
            || state.operation_epoch != epoch
            || state.sequence != sequence
            || state.request_digest != request_digest
            || state.phase != Phase::Pending
        {
            return Err(StoreDenied);
        }
        let phase = match outcome {
            Outcome::Committed => 2i64,
            Outcome::Rejected => 3i64,
        };
        let changed = tx
            .execute("UPDATE protected_state SET phase=?1 WHERE slot=1", [phase])
            .map_err(|_| StoreDenied)?;
        if changed != 1 {
            return Err(StoreDenied);
        }
        tx.commit().map_err(|_| StoreDenied)
    }

    /// Advance policy and digest atomically without resetting replay history
    /// or allowing a policy edit to discard unresolved native mutations.
    pub fn advance(
        &mut self,
        expected: u64,
        next: u64,
        digest: [u8; 32],
    ) -> Result<(), StoreDenied> {
        if next <= expected {
            return Err(StoreDenied);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreDenied)?;
        let state = snapshot(&tx, &self.domain)?;
        if state.epoch != expected || state.phase == Phase::Pending {
            return Err(StoreDenied);
        }
        let changed = tx
            .execute(
                "UPDATE protected_state SET epoch=?1,digest=?2 WHERE slot=1",
                params![next.to_be_bytes().as_slice(), digest.as_slice()],
            )
            .map_err(|_| StoreDenied)?;
        if changed != 1 {
            return Err(StoreDenied);
        }
        tx.commit().map_err(|_| StoreDenied)
    }
}
