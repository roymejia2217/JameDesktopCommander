//! CI-only systemd-issued process proof. No network listener, broker or file read.
//! This cannot establish the origin of the original desktop MCP process.
#[cfg(target_os = "linux")]
mod proof {
    use std::{
        fs,
        os::unix::fs::MetadataExt,
        path::Path,
        process::{Command, ExitCode, Stdio},
    };

    fn protected_image(path: &Path) -> Result<(), ()> {
        let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
        {
            return Err(());
        }
        Ok(())
    }

    fn issued_origin_test() -> Result<(), ()> {
        jdc_authority_service::verify_service_identity().map_err(|_| ())?;
        let issuer = std::env::current_exe().map_err(|_| ())?;
        let directory = issuer.parent().ok_or(())?;
        let custody = fs::symlink_metadata(directory).map_err(|_| ())?;
        if !custody.is_dir() || custody.uid() != 0 || custody.mode() & 0o022 != 0 {
            return Err(());
        }
        protected_image(&issuer)?;
        let child_image = directory.join("jdc-authority-systemd-issued-client");
        protected_image(&child_image)?;
        // Accept the separately provisioned root-owned image only. Its
        // executable mode is not an authentication credential on its own.
        // Child remains a tracked std::process::Child until it exits.
        let mut child = Command::new(&child_image)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ())?;
        let child_status = match child.wait() {
            Ok(status) => status,
            Err(_) => {
                // A failed wait is not proof of child completion.
                let _ = child.kill();
                let _ = child.wait();
                return Err(());
            }
        };
        if !child_status.success() {
            return Err(());
        }
        Ok(())
    }

    pub fn run() -> ExitCode {
        if jdc_authority_service::verify_service_identity().is_err() {
            eprintln!("E_IDENTITY_REQUIRED");
            return ExitCode::FAILURE;
        }
        if issued_origin_test().is_err() {
            eprintln!("E_SYSTEMD_ISSUED_CHILD_FAILED");
            return ExitCode::from(7);
        }
        // Code 6 means the real systemd-origin issuer successfully reaped
        // a child with a separately verified kernel-issued service token.
        eprintln!("E_SYSTEMD_ISSUED_CHILD_OK");
        ExitCode::from(6)
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    proof::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
