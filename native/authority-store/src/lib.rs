//! T011-C4h experimental transactional epoch engine.
//!
//! SQLite provides crash-oriented transaction atomicity, NOT rollback protection.
//! This module is NOT linked to an OS-protected service or MCP runtime.
//! Path-based opening is for offline feasibility testing ONLY; any production
//! broker MUST obtain and protect an OS-anchored storage handle and policy owner.

#[cfg(target_os = "linux")]
pub mod linux_replay_writer;
pub mod policy_bytes;
pub mod replay_ledger;
// Test-only: single-database policy/replay atomicity feasibility, not issuer.
#[cfg(test)]
mod coherent_transaction_proof;

use rusqlite::{params, Connection, OpenFlags, TransactionBehavior, MAIN_DB};
use std::{path::Path, time::Duration};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct StoreDenied;

/// Offline transaction proof. NOT a source of authorization: a filesystem
/// controller can replace the database with an older valid snapshot.
pub struct EpochStore {
    connection: Connection,
}

/// Immutable data-only policy-row identity. This is NOT an authenticated
/// policy, a protected OS directory, an antirollback witness or an I/O grant.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PolicySnapshot {
    epoch: u64,
    digest: [u8; 32],
}

impl PolicySnapshot {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

fn current(connection: &Connection) -> Result<(u64, [u8; 32]), StoreDenied> {
    // SQLite's CHECK(length(...)) can be bypassed by a writer holding the DB.
    // Never allocate a caller-sized BLOB before validating its exact shape.
    // Both bounded prefixes and their original lengths are from one SELECT.
    let (epoch_kind, epoch_len, epoch, digest_kind, digest_len, digest):
        (String, i64, Vec<u8>, String, i64, Vec<u8>) = connection
        .query_row(
            "SELECT typeof(epoch), length(epoch), substr(epoch,1,9), typeof(digest), length(digest), substr(digest,1,33) FROM protected_policy WHERE slot=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        ).map_err(|_| StoreDenied)?;
    if epoch_kind != "blob" || digest_kind != "blob" || epoch_len != 8 || digest_len != 32 {
        return Err(StoreDenied);
    }
    let epoch: [u8; 8] = epoch.try_into().map_err(|_| StoreDenied)?;
    let digest: [u8; 32] = digest.try_into().map_err(|_| StoreDenied)?;
    let epoch = u64::from_be_bytes(epoch);
    // Unprovisioned = exactly (0, all-zero); provisioned = positive epoch and
    // nonzero digest. Neither proves publisher authenticity or local rollback.
    if (epoch == 0 && digest != [0; 32]) || (epoch > 0 && digest == [0; 32]) {
        return Err(StoreDenied);
    }
    Ok((epoch, digest))
}

// Strict schema match is required both on open and inside each transaction.
// The IMMEDIATE write transaction keeps another writer from changing the schema
// between the validation and the actual mutation.
const SCHEMA_V1: &str =
    "CREATE TABLE protected_policy (slot INTEGER PRIMARY KEY CHECK(slot=1), epoch BLOB NOT NULL CHECK(length(epoch)=8), digest BLOB NOT NULL CHECK(length(digest)=32))";

fn exact_schema(connection: &Connection) -> Result<(), StoreDenied> {
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| StoreDenied)?;
    let schema_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| StoreDenied)?;
    if application_id != 0x4A444331 || schema_version != 1 {
        return Err(StoreDenied);
    }
    let unexpected: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type <> 'table' OR name <> 'protected_policy'",
        [], |row| row.get(0),
    ).map_err(|_| StoreDenied)?;
    let rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM protected_policy", [], |row| {
            row.get(0)
        })
        .map_err(|_| StoreDenied)?;
    if unexpected != 0 || rows != 1 {
        return Err(StoreDenied);
    }
    let actual: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'protected_policy'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreDenied)?;
    if actual != SCHEMA_V1 {
        return Err(StoreDenied);
    }
    Ok(())
}

impl EpochStore {
    /// Opens only an existing fixture. Missing, unreadable and corrupt stores
    /// deny; never creates or restores a policy database implicitly.
    ///
    /// WARNING: a pathname is not a protected OS handle, and this method
    /// cannot prevent symlink/reparse-point replacement or full DB replay.
    pub fn open_existing(path: &Path) -> Result<Self, StoreDenied> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| StoreDenied)?;
        // SQLite may silently fall back from READWRITE to read-only when the OS
        // rejects write access. Require the effective main DB mode, not flags.
        if connection.is_readonly(MAIN_DB).map_err(|_| StoreDenied)? {
            return Err(StoreDenied);
        }
        connection
            .busy_timeout(Duration::from_secs(3))
            .map_err(|_| StoreDenied)?;
        // DELETE journal avoids a persistent WAL sidecar. EXTRA requests
        // SQLite's strongest sync protocol for rollback-journal mode.
        let mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|_| StoreDenied)?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(StoreDenied);
        }
        connection
            .pragma_update(None, "synchronous", "EXTRA")
            .map_err(|_| StoreDenied)?;
        let sync: i64 = connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(|_| StoreDenied)?;
        if sync != 3 {
            return Err(StoreDenied);
        }
        // These markers are a format guard, not OS custody or authentication.
        exact_schema(&connection)?;
        current(&connection)?;
        Ok(Self { connection })
    }

    // Schema and row must be observed in one SQLite read transaction.
    // This does not authenticate the database file or external policy owner.
    fn read_consistent(&self) -> Result<(u64, [u8; 32]), StoreDenied> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(|_| StoreDenied)?;
        exact_schema(&tx)?;
        let snapshot = current(&tx)?;
        tx.commit().map_err(|_| StoreDenied)?;
        Ok(snapshot)
    }

    /// Read an existing provisioned epoch without granting any capability.
    pub fn read_epoch(&self) -> Result<u64, StoreDenied> {
        self.read_consistent().map(|(epoch, _)| epoch)
    }

    /// Read epoch and digest together using one SQLite SELECT statement.
    /// Require a provisioned, nonzero policy identity; there is no authority
    /// until an independent trusted OS watermark and owned root are verified.
    pub fn read_snapshot(&self) -> Result<PolicySnapshot, StoreDenied> {
        let (epoch, digest) = self.read_consistent()?;
        if epoch == 0 || digest.iter().all(|byte| *byte == 0) {
            return Err(StoreDenied);
        }
        Ok(PolicySnapshot { epoch, digest })
    }

    /// Persist a strictly increasing epoch and policy digest in one SQLite
    /// IMMEDIATE transaction. No caller authorization is performed.
    pub fn commit_after(
        &mut self,
        expected_previous: u64,
        next: u64,
        digest: [u8; 32],
    ) -> Result<(), StoreDenied> {
        if next == 0 || next <= expected_previous || digest.iter().all(|byte| *byte == 0) {
            return Err(StoreDenied);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreDenied)?;
        exact_schema(&tx)?;
        let (current_epoch, current_digest) = current(&tx)?;
        if current_epoch != expected_previous {
            return Err(StoreDenied);
        }
        // Never silently replace an unprovisioned or corrupt predecessor.
        // A valid v1 fixture begins with epoch=0 and an all-zero digest.
        // Any committed epoch must have a nonzero digest; this still does
        // NOT authenticate its origin or prevent replay of the whole DB.
        if (current_epoch == 0 && current_digest != [0; 32])
            || (current_epoch > 0 && current_digest == [0; 32])
        {
            return Err(StoreDenied);
        }
        let updated = tx
            .execute(
                "UPDATE protected_policy SET epoch = ?1, digest = ?2 WHERE slot = 1 AND epoch = ?3",
                params![
                    next.to_be_bytes().as_slice(),
                    digest.as_slice(),
                    current_epoch.to_be_bytes().as_slice()
                ],
            )
            .map_err(|_| StoreDenied)?;
        if updated != 1 {
            return Err(StoreDenied);
        }
        tx.commit().map_err(|_| StoreDenied)
    }
}
