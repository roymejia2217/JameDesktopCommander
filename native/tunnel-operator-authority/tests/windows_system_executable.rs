#[cfg(windows)]
mod windows {
    use tunnel_operator_authority::observe_os_schtasks_for_observation;

    #[test]
    fn native_windows_system_executable_is_observed_without_process_environment() {
        let observation = observe_os_schtasks_for_observation()
            .expect("native Windows system directory and schtasks.exe must be observable");
        assert!(observation.path.is_absolute());
        assert_eq!(
            observation.path.file_name().and_then(|name| name.to_str()),
            Some("schtasks.exe")
        );
        assert!(observation.link_count > 0);
    }

    #[test]
    fn poisoned_systemroot_does_not_redirect_native_system_executable() {
        // Child-only override: no global environment mutation and no race
        // with parallel tests or the user's installed tasks.
        let child = std::process::Command::new(
            std::env::current_exe().expect("exact test runner path"),
        )
        .args([
            "--exact",
            "windows::native_windows_system_executable_is_observed_without_process_environment",
        ])
        .env("SystemRoot", "C:\\JDC-NONEXISTENT-UNTRUSTED-SYSTEMROOT")
        .output()
        .expect("launch only the test runner fixture");
        assert!(
            child.status.success(),
            "native System32 observation must ignore injected SystemRoot"
        );
    }

    #[test]
    fn repeated_observation_preserves_native_file_identity() {
        let first = observe_os_schtasks_for_observation().expect("native observation");
        let second = observe_os_schtasks_for_observation().expect("second observation");
        assert_eq!(first.path, second.path);
        assert_eq!(first.volume_serial, second.volume_serial);
        assert_eq!(first.file_index, second.file_index);
    }
}
