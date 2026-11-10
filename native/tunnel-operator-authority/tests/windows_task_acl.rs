#![cfg(windows)]

use tunnel_operator_authority::{observe_registered_task_acl_for_observation, SidObservationError};

#[test]
fn task_acl_observer_rejects_arbitrary_names_without_registration_changes() {
    for invalid in ["", "..", "nested\\task", "task/child", "task\r\nsecond"] {
        assert_eq!(
            observe_registered_task_acl_for_observation(invalid),
            Err(SidObservationError::Unverifiable),
        );
    }
}

#[test]
fn task_acl_observer_rejects_unregistered_local_task() {
    assert_eq!(
        observe_registered_task_acl_for_observation("JDC-NONEXISTENT-READONLY-ACL-OBSERVATION",),
        Err(SidObservationError::Unverifiable),
    );
}
