#![cfg(windows)]
use jdc_authority_service::windows_pipe_peer::{
    observe_client_sid_after_read, observe_process_sid,
};
use std::{fs::File, os::windows::io::AsHandle};

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
fn process_token_sid_is_kernel_issued_and_bounded() {
    let sid = observe_process_sid().expect("query actual Windows process token");
    assert_eq!(
        jdc_authority_service::token_policy::bounded_sid_bytes(&sid),
        Some(sid.len())
    );
}
