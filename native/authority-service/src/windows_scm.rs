//! T011-C4m: Windows SCM-compatible, permanently deny-only service target.
//! Not installed or shipped. This is NOT an operational authorization broker.
#[cfg(windows)]
mod scm {
    use std::{ffi::OsString, process::ExitCode, time::Duration};
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
    // Explicit independent failure codes; no state ever reaches RUNNING.
    // Status codes are assigned solely by the reviewed deny-only policy.
    // No SCM state ever transitions to RUNNING.

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> ExitCode {
        match service_dispatcher::start(NAME, ffi_service_main) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => {
                // SCM is mandatory: an interactive run cannot simulate it.
                eprintln!("E_SCM_DISPATCHER_REQUIRED");
                ExitCode::FAILURE
            }
        }
    }

    fn service_main(_args: Vec<OsString>) {
        if report_denial().is_err() {
            eprintln!("E_SCM_STATUS_UNAVAILABLE");
        }
    }

    fn report_denial() -> windows_service::Result<()> {
        let handler = service_control_handler::register(NAME, |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

        // Inspect the *kernel process token*, never an environment variable,
        // CLI argument, process name, caller-controlled SID or JSON grant.
        // One TokenUser/TokenGroups/TokenPrivileges proof under one handle.
        // A failed native query maps to fail-closed SCM code 5, not code 2.
        let observation =
            jdc_authority_service::windows_token::observe_current_process_token().ok();
        let reason = jdc_authority_service::token_policy::scm_terminal_denial_code(observation);
        // Deliberately never signal StartPending -> Running: there is no
        // authenticated IPC, protected policy authority or native I/O broker.
        handler.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::ServiceSpecific(reason),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        })
    }
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    scm::run()
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("E_WINDOWS_SCM_ONLY");
    std::process::ExitCode::FAILURE
}
