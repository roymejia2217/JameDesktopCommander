#![cfg(windows)]
use jdc_authority_service::windows_pipe_peer::{
    observe_client_sid_after_read, observe_process_sid, verify_live_issued_peer_after_read,
};
use std::{
    fs::File,
    os::windows::io::{AsHandle, FromRawHandle, OwnedHandle},
};
use windows_sys::Win32::System::Threading::OpenProcess;

#[test]
fn ordinary_file_handle_cannot_supply_a_pipe_peer_identity() {
    let file = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("an existing regular file");
    assert!(observe_client_sid_after_read(file.as_handle()).is_err());
}

#[test]
fn second_non_pipe_handle_is_also_rejected() {
    let file = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
        .expect("an existing lockfile");
    assert!(observe_client_sid_after_read(file.as_handle()).is_err());
}

#[test]
fn ordinary_file_cannot_pass_named_pipe_origin_even_with_real_live_process_handle() {
    let file = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("ordinary file must exist");
    let raw = unsafe { OpenProcess(0x0010_1000, 0, std::process::id()) };
    assert!(
        !raw.is_null(),
        "actual process handle is mandatory for this negative control"
    );
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    assert_eq!(
        verify_live_issued_peer_after_read(file.as_handle(), process.as_handle()),
        Err(jdc_authority_service::IdentityDenied),
        "a file descriptor must not be mistaken for a named-pipe data channel",
    );
}

#[test]
fn process_token_sid_is_kernel_issued_and_bounded() {
    let sid = observe_process_sid().expect("query actual Windows process token");
    assert_eq!(
        jdc_authority_service::token_policy::bounded_sid_bytes(&sid),
        Some(sid.len())
    );
}
