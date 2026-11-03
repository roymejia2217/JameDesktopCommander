//! Disposable Windows SCM integration probe; never shipped or installed on user hosts.
//! Compiled in debug profile only; terminates immediately without granting I/O.
#[cfg(windows)]
mod windows {
    use std::{ffi::OsString, os::windows::fs::OpenOptionsExt, process::ExitCode, time::Duration};
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    const NAME: &str = "JameDesktopCommanderAuthority";
    const ACCEPTED_OBSERVATION: u32 = 41;
    const DENIED_DACL: u32 = 42;
    const ACCEPTED_ISOLATED_ROOT: u32 = 46;
    const DENIED_ISOLATED_ROOT: u32 = 47;
    const UNOPENABLE_FIXTURE: u32 = 43;
    const UNTRUSTED_IDENTITY: u32 = 44;
    const NOT_DEBUG_BUILD: u32 = 45;
    define_windows_service!(ffi_service_main, service_main);

    fn disposition(valid: bool) -> u32 {
        if valid {
            ACCEPTED_OBSERVATION
        } else {
            DENIED_DACL
        }
    }

    fn isolated_disposition(valid: bool) -> u32 {
        if valid {
            ACCEPTED_ISOLATED_ROOT
        } else {
            DENIED_ISOLATED_ROOT
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn real_positive_and_negative_proofs_have_distinct_terminal_codes() {
            assert_eq!(disposition(true), ACCEPTED_OBSERVATION);
            assert_eq!(disposition(false), DENIED_DACL);
        }

        #[test]
        fn actual_scm_isolated_root_requires_separate_positive_and_denial_verdicts() {
            assert_eq!(isolated_disposition(true), 46);
            assert_eq!(isolated_disposition(false), 47);
            assert_ne!(isolated_disposition(false), ACCEPTED_OBSERVATION);
            assert_ne!(isolated_disposition(true), DENIED_DACL);
        }
    }

    pub fn run() -> ExitCode {
        match service_dispatcher::start(NAME, ffi_service_main) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE, // Never impersonate an SCM run from a console.
        }
    }

    fn service_main(_args: Vec<OsString>) {
        if let Ok(handler) = service_control_handler::register(NAME, |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) {
            let reason = observe_once();
            let _ = handler.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::ServiceSpecific(reason),
                checkpoint: 0,
                wait_hint: Duration::ZERO,
                process_id: None,
            });
        }
    }

    fn observe_once() -> u32 {
        if !cfg!(debug_assertions) {
            return NOT_DEBUG_BUILD;
        }
        if jdc_authority_service::verify_service_identity().is_err() {
            return UNTRUSTED_IDENTITY;
        }
        let Some(stage) = std::env::current_exe().ok().and_then(|exe| {
            exe.parent()
                .and_then(|p| p.parent())
                .map(|p| p.to_path_buf())
        }) else {
            return UNOPENABLE_FIXTURE;
        };
        let open_dir = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
                .open(path)
        };
        let Ok(state) = open_dir(&stage.join("state")) else {
            return UNOPENABLE_FIXTURE;
        };
        let isolated = stage.join("isolated");
        // The isolated-root case exists ONLY in disposable hosted tests. No
        // caller parameter or client input can opt a production SCM service
        // into a grant; even a positive result is merely a terminal exit code.
        // Unexpected metadata lookup errors must not silently fall back to
        // the ordinary state-DACL observation.
        match std::fs::symlink_metadata(&isolated) {
            Ok(_) => {
                let validated_state =
                    jdc_authority_service::windows_policy_root::observe_preopened_service_state(
                        state,
                    )
                    .is_ok();
                let isolated_valid = match (open_dir(&stage), open_dir(&isolated)) {
                    (Ok(parent), Ok(root)) => {
                        jdc_authority_service::windows_policy_root::observe_preopened_isolated_service_root(
                            &parent, root,
                        )
                        .is_ok()
                    }
                    _ => false,
                };
                isolated_disposition(validated_state && isolated_valid)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => disposition(
                jdc_authority_service::windows_policy_root::observe_preopened_service_state(state)
                    .is_ok(),
            ),
            Err(_) => isolated_disposition(false),
        }
    }
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    windows::run()
}
#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
