#[cfg(windows)]
mod windows {
    use tunnel_operator_authority::{
        compare_registered_task_principal_for_observation, SidObservationError,
    };

    #[test]
    fn named_task_query_rejects_missing_registration() {
        // Query the real Windows Task Scheduler service without mutating tasks.
        assert_eq!(
            compare_registered_task_principal_for_observation(
                "JDC-issue270-unregistered-test-only-task-5738731"
            ),
            Err(SidObservationError::Unverifiable)
        );
    }

    #[test]
    fn traversal_and_invalid_task_names_are_rejected() {
        for bad in ["", "..", "\\OtherFolder\\Task", "Task/Name", "Nul\0Name"] {
            assert_eq!(
                compare_registered_task_principal_for_observation(bad),
                Err(SidObservationError::Unverifiable)
            );
        }
    }
}
