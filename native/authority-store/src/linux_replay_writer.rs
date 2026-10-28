//! Protected, systemd-service-identity SQLite writer with standard unix VFS.
//! Non-release: no capability dispatch until IPC and independent antirollback.
#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, params};
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let home = std::env::var_os("HOME").expect("Linux CI HOME");
        let temp = tempfile::tempdir_in(home).unwrap();
        let dir = temp.path().join("state");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("claims.sqlite3");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(concat!(
            "PRAGMA application_id=0x4A44434C; PRAGMA user_version=1;",
            "CREATE TABLE replay_claims (epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), ",
            "request BLOB NOT NULL CHECK(typeof(request)='blob' AND length(request)=16), ",
            "PRIMARY KEY(epoch,request)) WITHOUT ROWID"
        )).unwrap();
        drop(db);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (temp, dir)
    }
    fn id() -> [u8;16] {
        let mut n = [0x17;16]; n[6] = 0x40; n[8] = 0x80; n
    }
    #[test]
    fn protected_unix_sqlite_writer_persists_replay_and_denies_bad_custody() {
        let (_temp, dir) = fixture();
        let mut writer = LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).unwrap();
        writer.claim_once(id()).unwrap();
        assert!(writer.claim_once(id()).is_err());
        drop(writer);
        assert!(LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7)
            .unwrap().claim_once(id()).is_err());
        let db = Connection::open(dir.join("claims.sqlite3")).unwrap();
        let rows: i64 = db.query_row("SELECT COUNT(*) FROM replay_claims", [], |r| r.get(0)).unwrap();
        assert_eq!(rows, 1);
        let epoch: Vec<u8> = db.query_row("SELECT epoch FROM replay_claims", [], |r| r.get(0)).unwrap();
        assert_eq!(epoch, 7u64.to_be_bytes());
        drop(db);
        std::fs::set_permissions(dir.join("claims.sqlite3"), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).is_err());
        std::fs::set_permissions(dir.join("claims.sqlite3"), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(LinuxReplayIssuerLedger::open_protected_fixture(&dir, 7).is_err());
    }
}
