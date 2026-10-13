//! T011-C4h experimental transactional epoch engine.
//!
//! SQLite provides crash-oriented transaction atomicity, NOT rollback protection.
//! This module is NOT linked to an OS-protected service or MCP runtime.
//! Path-based opening is for offline feasibility testing ONLY; any production
//! broker MUST obtain and protect an OS-anchored storage handle and policy owner.

use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::{path::Path, time::Duration};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct StoreDenied;

/// Offline transaction proof. NOT a source of authorization: a filesystem
/// controller can replace the database with an older valid snapshot.
pub struct EpochStore {
    connection: Connection,
}

fn current(connection: &Connection) -> Result<(u64, [u8; 32]), StoreDenied> {
    let (epoch, digest): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT epoch, digest FROM protected_policy WHERE slot = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| StoreDenied)?;
    let epoch: [u8; 8] = epoch.try_into().map_err(|_| StoreDenied)?;
    let digest: [u8; 32] = digest.try_into().map_err(|_| StoreDenied)?;
    Ok((u64::from_be_bytes(epoch), digest))
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
        // Format markers and a single expected table reject accidental reuse
        // of an unrelated or silently migrated database. These fields are
        // NOT authentication: an attacker able to replace the DB can forge them.
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
        // Exact v1 constraints, not merely matching column names.
        // Intentional schema changes require an independently audited upgrade.
        const SCHEMA_V1: &str =
            "CREATE TABLE protected_policy (slot INTEGER PRIMARY KEY CHECK(slot=1), epoch BLOB NOT NULL CHECK(length(epoch)=8), digest BLOB NOT NULL CHECK(length(digest)=32))";
        let actual_schema: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'protected_policy'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| StoreDenied)?;
        if actual_schema != SCHEMA_V1 {
            return Err(StoreDenied);
        }
        current(&connection)?;
        Ok(Self { connection })
    }

    /// Read an existing provisioned epoch without granting any capability.
    pub fn read_epoch(&self) -> Result<u64, StoreDenied> {
        current(&self.connection).map(|(epoch, _)| epoch)
    }

    /// Persist a strictly increasing epoch and policy digest in one SQLite
    /// IMMEDIATE transaction. No caller authorization is performed.
    pub fn commit_after(
        &mut self,
        expected_previous: u64,
        next: u64,
        digest: [u8; 32],
    ) -> Result<(), StoreDenied> {
        if next == 0 || next <= expected_previous {
            return Err(StoreDenied);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreDenied)?;
        let (current_epoch, _) = current(&tx)?;
        if current_epoch != expected_previous {
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
