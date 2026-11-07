//! Disposable debug-only SCM test of an independently administered registry epoch.
//! Never packaged; never starts an operational authority or grants a file capability.
#[cfg(windows)]
mod windows {
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
    const ACCEPTED_EXACT_EPOCH: u32 = 51;
    const DENIED_KEY_OR_EPOCH: u32 = 52;
    const DENIED_SERVICE_IDENTITY: u32 = 53;
    const DENIED_NOT_DEBUG: u32 = 54;
    const DENIED_UNEXPECTED_REGISTRY_WRITE: u32 = 55;
    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> ExitCode {
        match service_dispatcher::start(NAME, ffi_service_main) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        }
    }
    fn service_main(_args: Vec<OsString>) {
        if let Ok(handler) = service_control_handler::register(NAME, |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) {
            let reason = observation();
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

    fn observation() -> u32 {
        if !cfg!(debug_assertions) {
            return DENIED_NOT_DEBUG;
        }
        if jdc_authority_service::verify_service_identity().is_err() {
            return DENIED_SERVICE_IDENTITY;
        }
        // The snapshot epoch is a synthetic fixed fixture. No SQLite policy
        // is consulted and this cannot issue an authority grant.
        match jdc_authority_service::windows_epoch_anchor::observe_fixed_epoch_floor() {
            Ok(observed) if observed.matches_snapshot(7, &[0xA5; 32]) => {
                // A valid observation must not imply permission to advance
                // the independently administered high-water registry value.
                if can_write_registry_key() {
                    DENIED_UNEXPECTED_REGISTRY_WRITE
                } else {
                    ACCEPTED_EXACT_EPOCH
                }
            }
            _ => DENIED_KEY_OR_EPOCH,
        }
    }
    fn can_write_registry_key() -> bool {
        use std::ptr;
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, KEY_WOW64_64KEY,
            REG_OPTION_OPEN_LINK,
        };
        const KEY: &str = "SOFTWARE\\JameDesktopCommander\\Authority\\EpochAnchor";
        let wide: Vec<u16> = KEY.encode_utf16().chain(std::iter::once(0)).collect();
        let mut handle: HKEY = ptr::null_mut();
        let code = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide.as_ptr(),
                REG_OPTION_OPEN_LINK,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                &mut handle,
            )
        };
        if code == 0 {
            // No mutation: detect a broken ACL by opening with write rights.
            unsafe {
                RegCloseKey(handle);
            }
            true
        } else {
            code != 5 /* Any unknown error is not proof of denial. */
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn unprovisioned_caller_cannot_assert_authority() {
            assert_eq!(observation(), DENIED_SERVICE_IDENTITY);
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
