//! Linux native read/disclosure integration; no installed authority or privileged fixtures.
#![cfg(target_os = "linux")]

use jdc_authority_service::{
    linux_message_origin::enable_writer_credentials, linux_peer::observe_kernel_peer,
    linux_read_disclosure::read_attested_regular_into_socket, policy_epoch::PolicyFence,
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::{Path, PathBuf},
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "jdc-authorized-read-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("inside.bin"), bytes).unwrap();
        Self(path)
    }
    fn root(&self) -> File {
        File::open(&self.0).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn pair() -> (UnixStream, UnixStream) {
    let (mut client, server) = UnixStream::pair().unwrap();
    enable_writer_credentials(&server).unwrap();
    client.write_all(b"R").unwrap();
    (client, server)
}

#[test]
fn actual_native_read_discloses_exact_bytes_once() {
    let fixture = Fixture::new(&[0, 255, 129, 42]);
    let (mut client, server) = pair();
    let peer = observe_kernel_peer(&server).unwrap();
    let policy = PolicyFence::new(1).unwrap();
    let ticket = policy.issue_read().unwrap();
    assert!(read_attested_regular_into_socket(
        &policy,
        &ticket,
        &server,
        peer,
        &fixture.root(),
        Path::new("inside.bin"),
        Duration::from_secs(1)
    )
    .is_ok());
    client.write_all(b"R").unwrap();
    assert!(
        read_attested_regular_into_socket(
            &policy,
            &ticket,
            &server,
            peer,
            &fixture.root(),
            Path::new("inside.bin"),
            Duration::from_secs(1)
        )
        .is_err(),
        "replay must never consume another request or disclose bytes"
    );
    assert_eq!(
        jdc_authority_service::linux_message_origin::receive_attested_byte(&server, peer).unwrap(),
        b'R',
        "rejected replay must leave a valid queued request untouched"
    );
    drop(server);
    let mut frame = Vec::new();
    client.read_to_end(&mut frame).unwrap();
    assert_eq!(frame, [b'A', 0, 0, 0, 4, 0, 255, 129, 42]);
}

#[test]
fn revoked_or_stale_ticket_discloses_no_bytes() {
    let fixture = Fixture::new(b"PRIVATE_FIXTURE");
    for revoked in [false, true] {
        let (mut client, server) = pair();
        let peer = observe_kernel_peer(&server).unwrap();
        let policy = PolicyFence::new(1).unwrap();
        let ticket = policy.issue_read().unwrap();
        if revoked {
            policy.revoke().unwrap();
        } else {
            policy.advance(2).unwrap();
        }
        assert!(read_attested_regular_into_socket(
            &policy,
            &ticket,
            &server,
            peer,
            &fixture.root(),
            Path::new("inside.bin"),
            Duration::from_secs(1)
        )
        .is_err());
        drop(server);
        let mut response = Vec::new();
        // Closing a socket with unread request data may reset the peer.
        let _ = client.read_to_end(&mut response);
        assert!(
            response.is_empty(),
            "revoked or stale policy must not disclose a prefix"
        );
    }
}

fn restrict_send_buffer(server: &UnixStream) {
    let size: libc::c_int = 4096;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                server.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        },
        0
    );
}

#[test]
fn stalled_peer_cannot_hold_policy_forever() {
    let fixture = Fixture::new(&vec![0x5a; 1024 * 1024]);
    let (_client, server) = pair();
    restrict_send_buffer(&server);
    let peer = observe_kernel_peer(&server).unwrap();
    let policy = PolicyFence::new(1).unwrap();
    let ticket = policy.issue_read().unwrap();
    let begin = Instant::now();
    assert!(read_attested_regular_into_socket(
        &policy,
        &ticket,
        &server,
        peer,
        &fixture.root(),
        Path::new("inside.bin"),
        Duration::from_millis(200)
    )
    .is_err());
    assert!(
        begin.elapsed() >= Duration::from_millis(50),
        "must reach real backpressure"
    );
    assert!(
        begin.elapsed() < Duration::from_secs(3),
        "one absolute response deadline"
    );
    policy.revoke().unwrap();
    assert!(policy.issue_read().is_err());
}

#[test]
fn revocation_waits_for_actual_socket_disclosure() {
    let payload = vec![0x73; 1024 * 1024];
    let fixture = Fixture::new(&payload);
    let (mut client, server) = pair();
    restrict_send_buffer(&server);
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let peer = observe_kernel_peer(&server).unwrap();
    let policy = Arc::new(PolicyFence::new(1).unwrap());
    let ticket = policy.issue_read().unwrap();
    let reader_policy = Arc::clone(&policy);
    let root = fixture.root();
    let reader = thread::spawn(move || {
        read_attested_regular_into_socket(
            &reader_policy,
            &ticket,
            &server,
            peer,
            &root,
            Path::new("inside.bin"),
            Duration::from_secs(5),
        )
    });
    let mut header = [0; 5];
    client.read_exact(&mut header).unwrap();
    assert_eq!(header, [b'A', 0, 16, 0, 0]);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let revoke_policy = Arc::clone(&policy);
    let revoker = thread::spawn(move || {
        entered_tx.send(()).unwrap();
        done_tx.send(revoke_policy.revoke()).unwrap();
    });
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        done_rx.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert_eq!(response, payload);
    reader.join().unwrap().unwrap();
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    revoker.join().unwrap();
    assert!(policy.issue_read().is_err());
}

#[test]
fn wrong_kernel_peer_never_receives_file_bytes() {
    let fixture = Fixture::new(b"PRIVATE_FIXTURE");
    let (mut client, server) = pair();
    let mut peer = observe_kernel_peer(&server).unwrap();
    peer.pid = -1;
    let policy = PolicyFence::new(1).unwrap();
    let ticket = policy.issue_read().unwrap();
    assert!(read_attested_regular_into_socket(
        &policy,
        &ticket,
        &server,
        peer,
        &fixture.root(),
        Path::new("inside.bin"),
        Duration::from_secs(1),
    )
    .is_err());
    drop(server);
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    assert!(response.is_empty());
}
