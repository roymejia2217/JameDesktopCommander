//! Non-shipping Linux falsification: SO_PEERCRED is not channel-custody proof.
//! A different real process writes on a connection passed by SCM_RIGHTS.
//! No trusted root, policy epoch, filesystem authorization or service is used.
#![cfg(target_os = "linux")]

use jdc_authority_service::{
    linux_message_origin::{enable_writer_credentials, receive_attested_byte},
    linux_peer::observe_kernel_peer,
    IdentityDenied,
};
use std::{
    env, fs,
    io::{Read, Write},
    mem::{align_of, size_of, zeroed},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct FixtureDir(PathBuf);
impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FixtureChild(Child);
impl Drop for FixtureChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

// Event-driven, bounded acceptance; never a sleep/retry state-poll loop.
fn accept_ready(listener: &UnixListener) -> UnixStream {
    let mut ready = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut ready, 1, 5_000) }, 1);
    assert_ne!(ready.revents & libc::POLLIN, 0);
    listener.accept().expect("owned control connection").0
}

fn send_fd(transport: &UnixStream, delegated: RawFd) {
    let mut marker = [0x51u8];
    let mut vector = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    let bytes = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    // CMSG_FIRSTHDR treats msg_control as an aligned cmsghdr pointer.
    // Vec<u8> promises only byte alignment; use native machine words instead.
    assert!(align_of::<usize>() >= align_of::<libc::cmsghdr>());
    let mut ancillary = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = bytes;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        assert!(!header.is_null());
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), delegated);
        assert_eq!(
            libc::sendmsg(transport.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
            1,
            "real kernel fd delegation must succeed"
        );
    }
}

fn receive_fd(transport: &UnixStream) -> UnixStream {
    let mut marker = [0u8];
    let mut vector = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    let bytes = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    // CMSG_FIRSTHDR treats msg_control as an aligned cmsghdr pointer.
    // Vec<u8> promises only byte alignment; use native machine words instead.
    assert!(align_of::<usize>() >= align_of::<libc::cmsghdr>());
    let mut ancillary = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = bytes;
    unsafe {
        assert_eq!(
            libc::recvmsg(transport.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC),
            1,
            "delegated descriptor must be received"
        );
        assert_eq!(marker, [0x51]);
        assert_eq!(message.msg_flags & libc::MSG_CTRUNC, 0);
        let header = libc::CMSG_FIRSTHDR(&message);
        assert!(!header.is_null());
        assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
        assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
        assert_eq!(
            (*header).cmsg_len,
            libc::CMSG_LEN(size_of::<RawFd>() as u32) as _
        );
        assert!(libc::CMSG_NXTHDR(&message, header).is_null());
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>());
        assert!(fd >= 0, "received kernel descriptor must be valid");
        UnixStream::from_raw_fd(fd)
    }
}

#[test]
fn original_connecting_client_fixture() {
    let Some(data_path) = env::var_os("JDC_T011_ORIGINAL_DATA_SOCKET") else {
        return;
    };
    let control_path = env::var_os("JDC_T011_ORIGINAL_CONTROL_SOCKET")
        .expect("original client is launched only by the test-owned parent");
    let data = UnixStream::connect(data_path).expect("original child opens data connection");
    let control =
        UnixStream::connect(control_path).expect("original child opens descriptor channel");
    control
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("bounded original descriptor send");
    send_fd(&control, data.as_raw_fd());
}

#[test]
fn delegated_writer_fixture() {
    let Some(path) = env::var_os("JDC_T011_DELEGATED_SOCKET") else {
        return; // Normal test discovery must not create a privileged listener.
    };
    let transport = UnixStream::connect(path).expect("connect to test-owned control socket");
    transport
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded descriptor reception");
    let mut delegated = receive_fd(&transport);
    delegated
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("bounded delegated write");
    delegated
        .write_all(&std::process::id().to_ne_bytes())
        .expect("send real delegated writer PID on transferred connection");
}

#[test]
fn kernel_writer_credentials_accept_only_the_original_request_process() {
    let (mut client, server) = UnixStream::pair().expect("local kernel socket pair");
    let original = observe_kernel_peer(&server).expect("kernel connection identity");
    enable_writer_credentials(&server).expect("kernel per-message credential option");
    client.write_all(b"R").expect("one legitimate byte");
    assert_eq!(receive_attested_byte(&server, original), Ok(b'R'));
}

#[test]
fn missing_kernel_writer_credentials_cannot_authorize_a_request() {
    let (mut client, server) = UnixStream::pair().expect("local kernel socket pair");
    let original = observe_kernel_peer(&server).expect("kernel connection identity");
    // In an unprovisioned transport no credentials may be inferred from
    // SO_PEERCRED as a fallback.
    client.write_all(b"R").expect("one unauthenticated byte");
    assert_eq!(
        receive_attested_byte(&server, original),
        Err(IdentityDenied)
    );
}

#[test]
fn ancillary_descriptor_delegation_is_not_an_authorized_request() {
    let (client, server) = UnixStream::pair().expect("local kernel socket pair");
    let original = observe_kernel_peer(&server).expect("kernel connection identity");
    enable_writer_credentials(&server).expect("kernel per-message credential option");
    let file = fs::File::open("/dev/null").expect("real descriptor fixture");
    send_fd(&client, file.as_raw_fd());
    assert_eq!(
        receive_attested_byte(&server, original),
        Err(IdentityDenied)
    );
}

#[test]
fn kernel_peer_snapshot_does_not_authenticate_writer_after_fd_transfer() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let dir = env::temp_dir().join(format!(
        "jdc-t011-scm-rights-{}-{}",
        std::process::id(),
        now.as_nanos()
    ));
    fs::create_dir(&dir).expect("unique test-owned fixture");
    let _cleanup = FixtureDir(dir.clone());
    let data_path = dir.join("data.sock");
    let original_control_path = dir.join("original.sock");
    let delegated_control_path = dir.join("delegated.sock");
    let data_listener = UnixListener::bind(&data_path).expect("test-owned data listener");
    let original_control_listener =
        UnixListener::bind(&original_control_path).expect("original-client transfer listener");
    let delegated_control_listener =
        UnixListener::bind(&delegated_control_path).expect("delegated-client transfer listener");

    // The original client is a separate, real kernel process, not the server.
    let mut original = FixtureChild(
        Command::new(env::current_exe().expect("current test binary"))
            .args(["--exact", "original_connecting_client_fixture"])
            .env("JDC_T011_ORIGINAL_DATA_SOCKET", &data_path)
            .env("JDC_T011_ORIGINAL_CONTROL_SOCKET", &original_control_path)
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn genuine original client"),
    );
    let mut server = accept_ready(&data_listener);
    let initial = observe_kernel_peer(&server).expect("kernel-issued original client credential");
    assert_eq!(initial.pid as u32, original.0.id());
    assert_eq!(initial.uid, unsafe { libc::geteuid() });
    assert_eq!(initial.gid, unsafe { libc::getegid() });
    enable_writer_credentials(&server).expect("receive kernel-issued writer credentials");
    let original_control = accept_ready(&original_control_listener);
    original_control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded original descriptor receipt");
    let original_socket = receive_fd(&original_control);
    assert!(original.0.wait().expect("original client exit").success());

    // A *different* process receives the already-connected data descriptor.
    // The original client has exited; its kernel connection snapshot persists.
    let mut delegated = FixtureChild(
        Command::new(env::current_exe().expect("current test binary"))
            .args(["--exact", "delegated_writer_fixture"])
            .env("JDC_T011_DELEGATED_SOCKET", &delegated_control_path)
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn independent delegated writer"),
    );
    assert_ne!(delegated.0.id(), original.0.id());
    assert_ne!(delegated.0.id(), std::process::id());
    let delegated_control = accept_ready(&delegated_control_listener);
    delegated_control
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("bounded delegated descriptor send");
    send_fd(&delegated_control, original_socket.as_raw_fd());
    drop(original_socket);

    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded data read");
    // A transferred fd retains the old SO_PEERCRED snapshot, but the
    // kernel attaches the *actual writer's* credentials to this request.
    assert_eq!(
        receive_attested_byte(&server, initial),
        Err(IdentityDenied),
        "a distinct same-UID writer cannot inherit the original connection",
    );
    let mut remainder = [0u8; size_of::<u32>() - 1];
    server
        .read_exact(&mut remainder)
        .expect("remaining delegated PID bytes");
    assert_eq!(remainder.as_slice(), &delegated.0.id().to_ne_bytes()[1..]);

    // SO_PEERCRED is the first client's connection-time snapshot; it cannot
    // identify who holds or writes through a later-transferred socket.
    let after = observe_kernel_peer(&server).expect("kernel snapshot after delegation");
    assert_eq!(after, initial);
    assert_ne!(after.pid as u32, delegated.0.id());
    assert!(delegated.0.wait().expect("delegated child exit").success());
    eprintln!("T011_LINUX_SCM_RIGHTS_PEER_PROVENANCE_FALSIFIED_NONRELEASE");
}
