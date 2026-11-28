//! Offline transactional journal proof. OS-protected custody remains mandatory.
use jdc_authority_store::mutation_journal::{Journal, Outcome, Phase};
use rusqlite::Connection;
use std::path::Path;
use tempfile::tempdir;

const DOMAIN: [u8; 32] = [7; 32];
const REQUEST: [u8; 32] = [9; 32];
fn provision(path: &Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "PRAGMA application_id=0x4A444331;
         PRAGMA user_version=2;
         CREATE TABLE protected_state (slot INTEGER PRIMARY KEY CHECK(slot=1), domain BLOB NOT NULL CHECK(typeof(domain)='blob' AND length(domain)=32), epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32), sequence BLOB NOT NULL CHECK(typeof(sequence)='blob' AND length(sequence)=8), phase INTEGER NOT NULL CHECK(phase IN (0,1,2,3)), operation_epoch BLOB NOT NULL CHECK(typeof(operation_epoch)='blob' AND length(operation_epoch)=8), request_digest BLOB NOT NULL CHECK(typeof(request_digest)='blob' AND length(request_digest)=32));
         INSERT INTO protected_state VALUES(1,zeroblob(32),x'0000000000000001',zeroblob(32),zeroblob(8),0,zeroblob(8),zeroblob(32));",
    ).unwrap();
    conn.execute(
        "UPDATE protected_state SET domain=?1 WHERE slot=1",
        [DOMAIN.as_slice()],
    )
    .unwrap();
}

#[test]
fn restart_preserves_unresolved_intent_and_refuses_all_new_work() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.sqlite3");
    provision(&path);
    {
        let mut journal = Journal::open_existing(&path, DOMAIN).unwrap();
        journal.begin(1, 1, REQUEST).unwrap();
        assert_eq!(journal.snapshot().unwrap().phase, Phase::Pending);
    }
    let mut reopened = Journal::open_existing(&path, DOMAIN).unwrap();
    assert_eq!(reopened.snapshot().unwrap().sequence, 1);
    assert_eq!(reopened.snapshot().unwrap().phase, Phase::Pending);
    assert!(reopened.begin(1, 1, REQUEST).is_err());
    assert!(reopened.begin(1, 2, REQUEST).is_err());
    assert!(reopened.advance(1, 2, [8; 32]).is_err());
    assert!(reopened.finish(1, 2, REQUEST, Outcome::Committed).is_err());
    assert!(reopened.finish(2, 1, REQUEST, Outcome::Committed).is_err());
    assert!(reopened.finish(1, 1, [8; 32], Outcome::Committed).is_err());
    assert_eq!(reopened.snapshot().unwrap().request_digest, REQUEST);
    // A trusted reconciler must determine the real outcome before finish.
    reopened.finish(1, 1, REQUEST, Outcome::Committed).unwrap();
    drop(reopened);
    let mut reopened = Journal::open_existing(&path, DOMAIN).unwrap();
    assert_eq!(reopened.snapshot().unwrap().phase, Phase::Committed);
    assert!(reopened.begin(1, 1, REQUEST).is_err());
    assert!(reopened.finish(1, 1, REQUEST, Outcome::Rejected).is_err());
    reopened.begin(1, 2, REQUEST).unwrap();
    reopened.finish(1, 2, REQUEST, Outcome::Rejected).unwrap();
    assert_eq!(reopened.snapshot().unwrap().phase, Phase::Rejected);
    reopened.advance(1, 2, [8; 32]).unwrap();
    assert!(reopened.begin(1, 3, REQUEST).is_err());
    assert!(reopened.begin(2, 2, REQUEST).is_err());
    reopened.begin(2, 3, REQUEST).unwrap();
}

#[test]
fn exactly_one_begin_wins_and_sequence_never_rewinds() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.sqlite3");
    provision(&path);
    let gate = std::sync::Barrier::new(2);
    let (a, b) = std::thread::scope(|s| {
        let a = s.spawn(|| {
            let mut j = Journal::open_existing(&path, DOMAIN).unwrap();
            gate.wait();
            j.begin(1, 1, REQUEST)
        });
        let b = s.spawn(|| {
            let mut j = Journal::open_existing(&path, DOMAIN).unwrap();
            gate.wait();
            j.begin(1, 1, REQUEST)
        });
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_ne!(a.is_ok(), b.is_ok());
    let mut j = Journal::open_existing(&path, DOMAIN).unwrap();
    assert_eq!(j.snapshot().unwrap().phase, Phase::Pending);
    j.finish(1, 1, REQUEST, Outcome::Rejected).unwrap();
    assert!(j.begin(1, 3, REQUEST).is_err());
    j.advance(1, u64::MAX, [1; 32]).unwrap();
    assert!(j.advance(u64::MAX, 1, [2; 32]).is_err());
    assert!(j.begin(1, 2, REQUEST).is_err());
    j.begin(u64::MAX, 2, REQUEST).unwrap();
}

#[test]
fn rejects_wrong_domain_missing_and_modified_schema() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.sqlite3");
    assert!(Journal::open_existing(&path, DOMAIN).is_err());
    assert!(!path.exists());
    provision(&path);
    assert!(Journal::open_existing(&path, [8; 32]).is_err());
    assert!(Journal::open_existing(&path, [0; 32]).is_err());
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER unexpected AFTER UPDATE ON protected_state BEGIN SELECT 1; END;",
    )
    .unwrap();
    assert!(Journal::open_existing(&path, DOMAIN).is_err());
}

#[test]
fn durable_intent_survives_process_exit_after_real_rename() {
    const CHILD: &str = "JDC_JOURNAL_CRASH_FIXTURE";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = std::path::PathBuf::from(root);
        let mut journal = Journal::open_existing(&root.join("policy.sqlite3"), DOMAIN).unwrap();
        journal.begin(1, 1, REQUEST).unwrap();
        std::fs::rename(root.join("stage"), root.join("target")).unwrap();
        // Simulate lost acknowledgement: no destructors or finish.
        std::process::exit(77);
    }
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.sqlite3");
    provision(&path);
    std::fs::write(dir.path().join("stage"), b"COMPLETE").unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "durable_intent_survives_process_exit_after_real_rename",
        ])
        .env(CHILD, dir.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(77));
    assert_eq!(
        std::fs::read(dir.path().join("target")).unwrap(),
        b"COMPLETE"
    );
    assert!(!dir.path().join("stage").exists());
    let mut journal = Journal::open_existing(&path, DOMAIN).unwrap();
    assert_eq!(journal.snapshot().unwrap().phase, Phase::Pending);
    assert!(journal.begin(1, 2, REQUEST).is_err());
}

#[test]
fn terminal_outcome_keeps_original_operation_epoch_after_policy_advance() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.sqlite3");
    provision(&path);
    let mut journal = Journal::open_existing(&path, DOMAIN).unwrap();
    journal.begin(1, 1, REQUEST).unwrap();
    journal.finish(1, 1, REQUEST, Outcome::Committed).unwrap();
    journal.advance(1, 2, [8; 32]).unwrap();
    drop(journal);
    let reopened = Journal::open_existing(&path, DOMAIN).unwrap();
    let state = reopened.snapshot().unwrap();
    assert_eq!(state.epoch, 2);
    assert_eq!(state.operation_epoch, 1);
    assert_eq!(state.request_digest, REQUEST);
    assert_eq!(state.sequence, 1);
    assert_eq!(state.phase, Phase::Committed);
}
