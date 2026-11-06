//! Experimental OS-native local file transaction for issue #248.
//! Only synthetic fixture tests are authorized until registered service
//! identity, native operator authority, and provider authentication are wired.
//! No remote MCP route, CLI, key issuer, or installed service invokes this.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{recover_local_file, LocalFileRotation, RecoveryOutcome, RotationDenied};
