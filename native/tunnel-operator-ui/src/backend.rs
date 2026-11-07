use crate::{InstalledLayout, MAX_SNAPSHOT_BYTES, Overview, parse_overview};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
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

// The collector must consume bounded stdout *while* the child is running.
// Waiting for exit before reading the pipe can deadlock when the child emits
// more than the operating system's pipe capacity.
fn terminate_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn collect_backend_output(mut child: Child, timeout: Duration) -> Result<Vec<u8>, BackendError> {
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        return Err(BackendError::Unavailable);
    };
    let started = std::time::Instant::now();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = stdout
            .take((MAX_SNAPSHOT_BYTES + 1) as u64)
            .read_to_end(&mut bytes);
        let _ = sender.send((read, bytes));
    });

    let (read, bytes) = match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            terminate_and_reap(&mut child);
            return Err(BackendError::TimedOut);
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            terminate_and_reap(&mut child);
            return Err(BackendError::Failed);
        }
    };
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        terminate_and_reap(&mut child);
        return Err(BackendError::TooLarge);
    }
    if read.is_err() {
        terminate_and_reap(&mut child);
        return Err(BackendError::Failed);
    }

    // The same deadline applies to both output capture and process exit.
    // A process that closes stdout but never exits must not hang the GUI.
    let remaining = timeout.saturating_sub(started.elapsed());
    let status = match child.wait_timeout(remaining) {
        Ok(Some(exit)) => exit,
        Ok(None) => {
            terminate_and_reap(&mut child);
            return Err(BackendError::TimedOut);
        }
        Err(_) => {
            terminate_and_reap(&mut child);
            return Err(BackendError::Failed);
        }
    };
    if !status.success() {
        return Err(BackendError::Failed);
    }
    Ok(bytes)
}

/// Only the installed sibling binary + installed JS entrypoint are callable.
pub fn read_installed_overview(layout: &InstalledLayout) -> Result<Overview, BackendError> {
    require_regular_file(&layout.node)?;
    require_regular_file(&layout.entrypoint)?;

    let child = Command::new(&layout.node)
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

    let bytes = collect_backend_output(child, Duration::from_secs(crate::BACKEND_TIMEOUT_SECONDS))?;
    parse_overview(&bytes).map_err(|_| BackendError::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests spawn only the Rust test binary; they do not require Node,
    // a shell, a running tunnel, credentials or an installed MCP runtime.
    #[test]
    fn child_emits_output_for_bounded_capture() {
        use std::io::Write;
        match std::env::var("JDC_TEST_OPERATOR_STDOUT_MODE").as_deref() {
            Ok("oversized") => {
                std::io::stdout()
                    .write_all(&vec![b'x'; MAX_SNAPSHOT_BYTES + 8192])
                    .expect("test child must write its oversized payload");
            }
            Ok("small") => {
                std::io::stdout()
                    .write_all(b"JDC_TEST_VALID_CHILD_OUTPUT")
                    .expect("test child must write its small payload");
            }
            Ok("nonzero") => std::process::exit(42),
            Ok("hang") => thread::sleep(Duration::from_secs(3)),
            _ => {}
        }
    }

    fn test_child(mode: &str) -> Child {
        Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "backend::tests::child_emits_output_for_bounded_capture",
                "--nocapture",
            ])
            .env("JDC_TEST_OPERATOR_STDOUT_MODE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bounded test child")
    }

    #[test]
    fn oversized_child_stdout_is_rejected_before_process_exit() {
        // A child writing above the pipe capacity must not be misclassified
        // as a timeout while the reader already knows the output is too large.
        let started = std::time::Instant::now();
        let result = collect_backend_output(test_child("oversized"), Duration::from_secs(6));
        assert_eq!(result.unwrap_err(), BackendError::TooLarge);
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "oversized output must be rejected without waiting for process timeout"
        );
    }

    #[test]
    fn bounded_child_output_preserves_success_and_nonzero_failure() {
        let bytes = collect_backend_output(test_child("small"), Duration::from_secs(6)).unwrap();
        assert!(
            bytes
                .windows(b"JDC_TEST_VALID_CHILD_OUTPUT".len())
                .any(|window| window == b"JDC_TEST_VALID_CHILD_OUTPUT")
        );
        assert_eq!(
            collect_backend_output(test_child("nonzero"), Duration::from_secs(6)),
            Err(BackendError::Failed)
        );
    }

    #[test]
    fn child_that_never_exits_is_killed_and_times_out() {
        let started = std::time::Instant::now();
        assert_eq!(
            collect_backend_output(test_child("hang"), Duration::from_millis(250)),
            Err(BackendError::TimedOut)
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the child must be killed and reaped before its unbounded work finishes"
        );
    }

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
