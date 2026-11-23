//! OS-independent policy freshness and revocation linearization tests.
//! These do not assert the authority of the initial revision source.
use jdc_authority_service::policy_epoch::PolicyFence;
use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};

#[test]
fn rejects_stale_and_revoked_operations_before_any_side_effect() {
    let policy = PolicyFence::new(10).expect("initial protected revision");
    assert_eq!(
        policy.execute_once(&policy.issue_read().unwrap(), || vec![0, 255, 129]),
        Ok(vec![0, 255, 129])
    );
    let stale = policy.issue_read().unwrap();
    policy.advance(11).unwrap();
    let mut invoked = false;
    assert!(policy
        .execute_once(&stale, || {
            invoked = true;
            42
        })
        .is_err());
    assert!(
        !invoked,
        "stale operations may not touch native file handles"
    );
    let pending = policy.issue_read().unwrap();
    policy.revoke().unwrap();
    assert!(policy
        .execute_once(&pending, || {
            invoked = true;
            42
        })
        .is_err());
    assert!(
        !invoked,
        "revoked operations may not touch native file handles"
    );
}

#[test]
fn revision_advance_refuses_rollback_and_resurrected_old_grants() {
    assert!(PolicyFence::new(0).is_err());
    let policy = PolicyFence::new(100).unwrap();
    let old_100 = policy.issue_read().unwrap();
    assert!(policy.advance(100).is_err());
    assert!(policy.advance(99).is_err());
    policy.advance(101).unwrap();
    assert!(policy.execute_once(&old_100, || b"old".to_vec()).is_err());
    assert_eq!(
        policy.execute_once(&policy.issue_read().unwrap(), || b"new".to_vec()),
        Ok(b"new".to_vec())
    );
    let old_101 = policy.issue_read().unwrap();
    policy.revoke().unwrap();
    assert!(policy.advance(100).is_err());
    policy.advance(102).unwrap();
    assert!(policy.execute_once(&old_101, || b"old".to_vec()).is_err());
    assert_eq!(
        policy.execute_once(&policy.issue_read().unwrap(), || b"new".to_vec()),
        Ok(b"new".to_vec())
    );
}

#[test]
fn revocation_completion_follows_last_admitted_operations_disclosure() {
    let policy = Arc::new(PolicyFence::new(5).unwrap());
    let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let reader_ticket = policy.issue_read().unwrap();
    let reader_policy = Arc::clone(&policy);
    let reader_order = Arc::clone(&order);
    let reader = thread::spawn(move || {
        reader_policy.execute_once(&reader_ticket, || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            reader_order.lock().unwrap().push("disclosure_complete");
            b"exact".to_vec()
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let pending_ticket = policy.issue_read().unwrap();
    let revoker_policy = Arc::clone(&policy);
    let revoker_order = Arc::clone(&order);
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let revoker = thread::spawn(move || {
        started_tx.send(()).unwrap();
        revoker_policy.revoke().unwrap();
        revoker_order.lock().unwrap().push("revocation_complete");
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    release_tx.send(()).unwrap();
    assert_eq!(reader.join().unwrap(), Ok(b"exact".to_vec()));
    revoker.join().unwrap();
    assert_eq!(
        *order.lock().unwrap(),
        vec!["disclosure_complete", "revocation_complete"]
    );
    assert!(policy
        .execute_once(&pending_ticket, || b"forbidden".to_vec())
        .is_err());
}

#[test]
fn exactly_one_concurrent_claim_can_execute_a_native_operation_ticket() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier,
    };
    let policy = Arc::new(PolicyFence::new(9).unwrap());
    let ticket = Arc::new(policy.issue_read().unwrap());
    let start = Arc::new(Barrier::new(3));
    let disclosed = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let policy = Arc::clone(&policy);
        let ticket = Arc::clone(&ticket);
        let start = Arc::clone(&start);
        let disclosed = Arc::clone(&disclosed);
        workers.push(thread::spawn(move || {
            start.wait();
            policy.execute_once(&ticket, || {
                disclosed.fetch_add(1, Ordering::SeqCst);
                b"one-response".to_vec()
            })
        }));
    }
    start.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|task| task.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(disclosed.load(Ordering::SeqCst), 1);
    assert!(policy
        .execute_once(&ticket, || panic!("replay may not run"))
        .is_err());
}

#[test]
fn tickets_are_consumed_on_stale_epoch_and_unissued_after_revocation() {
    let policy = PolicyFence::new(12).unwrap();
    let stale = policy.issue_read().unwrap();
    policy.advance(13).unwrap();
    assert!(policy.execute_once(&stale, || 123).is_err());
    assert!(policy
        .execute_once(&stale, || panic!("spent ticket"))
        .is_err());
    let current = policy.issue_read().unwrap();
    assert_eq!(
        policy.execute_once(&current, || b"allowed".to_vec()),
        Ok(b"allowed".to_vec())
    );
    policy.revoke().unwrap();
    assert!(policy.issue_read().is_err());
    assert!(policy
        .execute_once(&current, || panic!("spent ticket"))
        .is_err());
}

#[test]
fn identical_numeric_epoch_from_another_policy_instance_is_not_a_grant() {
    let left = PolicyFence::new(44).unwrap();
    let right = PolicyFence::new(44).unwrap();
    let ticket = left.issue_read().unwrap();
    assert!(right
        .execute_once(&ticket, || panic!("foreign ticket"))
        .is_err());
    assert!(left
        .execute_once(&ticket, || panic!("failed attempt consumed"))
        .is_err());
    let fresh = left.issue_read().unwrap();
    assert_eq!(
        left.execute_once(&fresh, || b"approved".to_vec()),
        Ok(b"approved".to_vec())
    );
}
