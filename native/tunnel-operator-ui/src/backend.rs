use crate::{InstalledLayout, MAX_SNAPSHOT_BYTES, Overview, parse_overview};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use wait_timeout::ChildExt;

/// Fixed, sanitized reasons only. No raw stderr, profile names, paths or tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendError {
    Unavailable,
    UnsafeLayout,
    TimedOut,
    Failed,
    TooLarge,
    InvalidResponse,
}
impl BackendError {
    pub fn display(self) -> &'static str {
        match self {
            Self::Unavailable => "Installed backend is unavailable.",
            Self::UnsafeLayout => "Installed backend location is not trusted.",
            Self::TimedOut => "Local backend diagnostic timed out.",
            Self::Failed => "Local backend diagnostic was not completed.",
            Self::TooLarge => "Local backend returned an oversized response.",
            Self::InvalidResponse => "Local backend response was incompatible.",
        }
    }
}

fn require_regular_file(path: &Path) -> Result<(), BackendError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BackendError::Unavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(BackendError::UnsafeLayout);
    }
    Ok(())
}

/// Only the installed sibling binary + installed JS entrypoint are callable.
pub fn read_installed_overview(layout: &InstalledLayout) -> Result<Overview, BackendError> {
    require_regular_file(&layout.node)?;
    require_regular_file(&layout.entrypoint)?;

    let mut child = Command::new(&layout.node)
        .arg(&layout.entrypoint)
        .args(layout.arguments())
        .current_dir(&layout.root)
        // Do not allow inherited Node module injections into the installed runtime.
        .env_remove("NODE_OPTIONS")
        .env_remove("NODE_PATH")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| BackendError::Unavailable)?;

    let stdout = child.stdout.take().ok_or(BackendError::Unavailable)?;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = stdout
            .take((MAX_SNAPSHOT_BYTES + 1) as u64)
            .read_to_end(&mut bytes);
        let _ = sender.send((read, bytes));
    });
    let status = match child.wait_timeout(Duration::from_secs(crate::BACKEND_TIMEOUT_SECONDS)) {
        Ok(Some(exit)) => exit,
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(BackendError::TimedOut);
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(BackendError::Failed);
        }
    };
    if !status.success() {
        return Err(BackendError::Failed);
    }
    let (read, bytes) = receiver
        .recv_timeout(Duration::from_millis(500))
        .map_err(|_| BackendError::Failed)?;
    read.map_err(|_| BackendError::Failed)?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(BackendError::TooLarge);
    }
    parse_overview(&bytes).map_err(|_| BackendError::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_messages_do_not_reflect_untrusted_input() {
        for e in [
            BackendError::Unavailable,
            BackendError::UnsafeLayout,
            BackendError::TimedOut,
            BackendError::Failed,
            BackendError::TooLarge,
            BackendError::InvalidResponse,
        ] {
            assert!(!e.display().contains("api_key"));
            assert!(!e.display().contains("C:\\"));
            assert!(!e.display().contains("token="));
        }
    }
}
