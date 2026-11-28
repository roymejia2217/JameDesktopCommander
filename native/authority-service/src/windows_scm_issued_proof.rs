//! CI-only SCM issuer-origin and distinct-principal process-custody proof.
//! The fixed rendezvous file carries fixture metadata, never broker grants.
//! This is NOT a production SCM image, shipping IPC authority or an MCP read.
#[cfg(windows)]
#[path = "windows_scm_fixture_observation.rs"]
mod observation;
#[cfg(windows)]
mod proof {
    use jdc_authority_service::{
        windows_issued_client::IssuedClient, windows_token::ScmFixtureRole, IdentityDenied,
    };
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
    #[derive(Clone, Copy)]
    enum Mode {
        Legacy,
        Issuer,
        Observer,
    }
    impl Mode {
        fn from_args() -> Option<Self> {
            let mut args = std::env::args_os().skip(1);
            match (args.next().as_deref(), args.next()) {
                (None, None) => Some(Self::Legacy),
                (Some(arg), None) if arg == "--issuer-observer-proof" => Some(Self::Issuer),
                (Some(arg), None) if arg == "--authority-observer-proof" => Some(Self::Observer),
                _ => None,
            }
        }
        fn name(self) -> &'static str {
            match self {
                Self::Issuer => ScmFixtureRole::Issuer.service_name(),
                Self::Legacy | Self::Observer => NAME,
            }
        }
    }
    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> ExitCode {
        let Some(mode) = Mode::from_args() else {
            return ExitCode::FAILURE;
        };
        match service_dispatcher::start(mode.name(), ffi_service_main) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        }
    }

    fn service_main(_args: Vec<OsString>) {
        let Some(mode) = Mode::from_args() else {
            return;
        };
        let result = match mode {
            Mode::Legacy => report_proof(),
            Mode::Issuer => report_issuer(),
            Mode::Observer => report_observer(),
        };
        if result.is_err() {
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

    fn report_observer() -> windows_service::Result<()> {
        let handler = service_control_handler::register(NAME, |command| match command {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        let reason = if super::observation::observe().is_ok() {
            8
        } else {
            9
        };
        terminal(&handler, reason)
    }

    fn report_issuer() -> windows_service::Result<()> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let handler = service_control_handler::register(
            ScmFixtureRole::Issuer.service_name(),
            move |command| match command {
                ServiceControl::Stop => {
                    let _ = sender.try_send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )?;
        let reason = if super::observation::issue(&handler, receiver).is_ok() {
            10
        } else {
            11
        };
        terminal(&handler, reason)
    }

    fn terminal(
        handler: &service_control_handler::ServiceStatusHandle,
        reason: u32,
    ) -> windows_service::Result<()> {
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

    fn report_proof() -> windows_service::Result<()> {
        let handler = service_control_handler::register(NAME, |command| match command {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        // Never RUNNING, no listener and no file root. Status 6 is only
        // reached after the real SCM process successfully issues a child.
        let reason = if issued_origin_test().is_ok() { 6 } else { 7 };
        terminal(&handler, reason)
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
