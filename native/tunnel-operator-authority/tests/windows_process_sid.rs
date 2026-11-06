#[cfg(windows)]
mod windows {
    use tunnel_operator_authority::{
        compare_current_process_user_sid, observe_current_process_user_sid, ProcessSidEvidence,
        SidObservationError,
    };

    #[test]
    fn kernel_token_user_sid_matches_its_own_observation() {
        let observed = observe_current_process_user_sid().expect("query real TokenUser");
        assert_eq!(
            compare_current_process_user_sid(&observed),
            Ok(ProcessSidEvidence::SameAccount)
        );
    }

    #[test]
    fn a_different_well_formed_sid_must_not_match() {
        let mut other = observe_current_process_user_sid().expect("query real TokenUser");
        *other.last_mut().expect("SID has a subauthority") ^= 1;
        assert_eq!(
            compare_current_process_user_sid(&other),
            Ok(ProcessSidEvidence::DifferentAccount)
        );
    }
    #[test]
    fn malformed_sid_cannot_be_treated_as_a_principal() {
        let mut invalid = observe_current_process_user_sid().expect("query real TokenUser");
        invalid[0] = 0; // SID revision must be exactly one.
        assert_eq!(
            compare_current_process_user_sid(&invalid),
            Err(SidObservationError::Unverifiable)
        );
        assert_eq!(
            compare_current_process_user_sid(&[1, 1, 0]),
            Err(SidObservationError::Unverifiable)
        );
    }
}
