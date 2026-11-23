//! CI-only SCM issuer-origin proof. It never runs a broker or reads files.
//! A real virtual-account service creates and retains an OS-protected child.
//! This is NOT a production SCM image, IPC authentication or an MCP read.
#[cfg(windows)]
mod proof {
    use jdc_authority_service::{windows_issued_client::IssuedClient, IdentityDenied};
    use std::{
        ffi::{OsStr, OsString},
        process::ExitCode,
        time::Duration,
    };
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
    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> ExitCode {
        match service_dispatcher::start(NAME, ffi_service_main) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        }
    }

    fn service_main(_args: Vec<OsString>) {
        if report_proof().is_err() {
            eprintln!("E_SCM_ISSUER_STATUS_UNAVAILABLE");
        }
    }

    fn issued_origin_test() -> Result<(), IdentityDenied> {
        jdc_authority_service::verify_service_identity()?;
        let service_exe = std::env::current_exe().map_err(|_| IdentityDenied)?;
        let directory = service_exe.parent().ok_or(IdentityDenied)?;
        let child_image = directory.join("jdc-authority-scm-issued-client.exe");
        let mut command = OsString::from("\"");
        command.push(child_image.as_os_str());
        command.push(OsStr::new("\""));
        let system_root = std::env::var("SystemRoot").map_err(|_| IdentityDenied)?;
        let mut child = IssuedClient::launch_suspended(
            &child_image,
            &command,
            &[("SystemRoot", system_root.as_str())],
        )?;
        child.resume()?;
        child.wait_for_exit(Duration::from_secs(10))?;
        if child.exit_code()? != 0 {
            return Err(IdentityDenied);
        }
        Ok(())
    }

    fn report_proof() -> windows_service::Result<()> {
        let handler = service_control_handler::register(NAME, |command| match command {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        // Never RUNNING, no listener and no file root. Status 6 is only
        // reached after the real SCM process successfully issues a child.
        let reason = if issued_origin_test().is_ok() { 6 } else { 7 };
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
    proof::run()
}
#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
