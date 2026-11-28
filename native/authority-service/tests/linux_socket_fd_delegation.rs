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
    let mut data = UnixStream::connect(data_path).expect("original child opens data connection");
    let mut control =
        UnixStream::connect(control_path).expect("original child opens descriptor channel");
    control
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("bounded original descriptor send");
    let frame_mode = env::var("JDC_T011_ORIGINAL_FRAME_PREFIX").ok();
    if frame_mode.is_some() {
        control
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut ready = [0u8; 1];
        control.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"C");
        data.write_all(&6u32.to_be_bytes()).unwrap();
        data.write_all(b"AB").unwrap();
        if frame_mode.as_deref() == Some("complete") {
            data.write_all(b"CDEF").unwrap();
        }
    }
    send_fd(&control, data.as_raw_fd());
    if frame_mode.is_some() {
        let mut done = [0u8; 1];
        control.read_exact(&mut done).unwrap();
        assert_eq!(&done, b"D");
    }
}

#[test]
fn delegated_writer_fixture() {
    let Some(path) = env::var_os("JDC_T011_DELEGATED_SOCKET") else {
        return; // Normal test discovery must not create a privileged listener.
    };
    let mut transport = UnixStream::connect(path).expect("connect to test-owned control socket");
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
    if env::var_os("JDC_T011_DELEGATED_FRAME_SUFFIX").is_some() {
        transport.write_all(b"Q").unwrap();
        let mut verdict = [0u8; 1];
        transport.read_exact(&mut verdict).unwrap();
        assert_eq!(&verdict, b"D");
    }
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
    exercise_actual_delegation(None);
}

#[test]
fn authenticated_prefix_cannot_authorize_a_delegated_payload_suffix() {
    exercise_actual_delegation(Some("mixed"));
}

#[test]
fn complete_frame_from_original_live_process_is_accepted() {
    exercise_actual_delegation(Some("complete"));
}

fn exercise_actual_delegation(frame_mode: Option<&str>) {
    let framed = frame_mode.is_some();
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
    let mut command = Command::new(env::current_exe().expect("current test binary"));
    command
        .args(["--exact", "original_connecting_client_fixture"])
        .env("JDC_T011_ORIGINAL_DATA_SOCKET", &data_path)
        .env("JDC_T011_ORIGINAL_CONTROL_SOCKET", &original_control_path)
        .stdout(Stdio::null());
    if let Some(mode) = frame_mode {
        command.env("JDC_T011_ORIGINAL_FRAME_PREFIX", mode);
    }
    let mut original = FixtureChild(command.spawn().expect("spawn genuine original client"));
    let mut server = accept_ready(&data_listener);
    let initial = observe_kernel_peer(&server).expect("kernel-issued original client credential");
    assert_eq!(initial.pid as u32, original.0.id());
    assert_eq!(initial.uid, unsafe { libc::geteuid() });
    assert_eq!(initial.gid, unsafe { libc::getegid() });
    enable_writer_credentials(&server).expect("receive kernel-issued writer credentials");
    let mut original_control = accept_ready(&original_control_listener);
    if framed {
        original_control
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        original_control.write_all(b"C").unwrap();
    }
    original_control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded original descriptor receipt");
    let original_socket = receive_fd(&original_control);
    if frame_mode == Some("complete") {
        assert_eq!(
            jdc_authority_service::linux_message_origin::receive_attested_frame(
                &server,
                initial,
                6,
                Duration::from_secs(5)
            ),
            Ok(b"ABCDEF".to_vec())
        );
        original_control.write_all(b"D").unwrap();
        assert!(original.0.wait().unwrap().success());
        return;
    }
    if !framed {
        assert!(original.0.wait().expect("original client exit").success());
    } else {
        assert!(original.0.try_wait().unwrap().is_none());
    }

    // A different process receives the already-connected descriptor.
    // The framed test keeps the authenticated prefix writer alive; the
    // byte test retains the historical after-exit falsification.
    let mut command = Command::new(env::current_exe().expect("current test binary"));
    command
        .args(["--exact", "delegated_writer_fixture"])
        .env("JDC_T011_DELEGATED_SOCKET", &delegated_control_path)
        .stdout(Stdio::null());
    if framed {
        command.env("JDC_T011_DELEGATED_FRAME_SUFFIX", "1");
    }
    let mut delegated = FixtureChild(command.spawn().expect("spawn independent delegated writer"));
    assert_ne!(delegated.0.id(), original.0.id());
    assert_ne!(delegated.0.id(), std::process::id());
    let mut delegated_control = accept_ready(&delegated_control_listener);
    delegated_control
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("bounded delegated descriptor send");
    send_fd(&delegated_control, original_socket.as_raw_fd());
    drop(original_socket);
    if framed {
        delegated_control
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut queued = [0u8; 1];
        delegated_control.read_exact(&mut queued).unwrap();
        assert_eq!(&queued, b"Q");
        assert!(original.0.try_wait().unwrap().is_none());
        assert!(delegated.0.try_wait().unwrap().is_none());
    }

    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded data read");
    // A transferred fd retains the old SO_PEERCRED snapshot, but the
    // kernel attaches the *actual writer's* credentials to this request.
    if framed {
        // The original process really sent the length and two payload
        // bytes. The second process supplies the remaining four bytes.
        // Authentication must not be cached from the header.
        assert_eq!(
            jdc_authority_service::linux_message_origin::receive_attested_frame(
                &server,
                initial,
                6,
                Duration::from_secs(5)
            ),
            Err(IdentityDenied)
        );
    } else {
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
    }

    // SO_PEERCRED is the first client's connection-time snapshot; it cannot
    // identify who holds or writes through a later-transferred socket.
    let after = observe_kernel_peer(&server).expect("kernel snapshot after delegation");
    assert_eq!(after, initial);
    assert_ne!(after.pid as u32, delegated.0.id());
    if framed {
        assert!(delegated.0.try_wait().unwrap().is_none());
        delegated_control.write_all(b"D").unwrap();
    }
    assert!(delegated.0.wait().expect("delegated child exit").success());
    if framed {
        assert!(original.0.try_wait().unwrap().is_none());
        original_control.write_all(b"D").unwrap();
        assert!(original.0.wait().unwrap().success());
    }
    eprintln!("T011_LINUX_SCM_RIGHTS_PEER_PROVENANCE_FALSIFIED_NONRELEASE");
}

#[test]
fn framed_requests_require_all_fragments_and_bounded_length() {
    use jdc_authority_service::linux_message_origin::receive_attested_frame;
    let (mut client, server) = UnixStream::pair().unwrap();
    let peer = observe_kernel_peer(&server).unwrap();
    enable_writer_credentials(&server).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            client.write_all(&5u32.to_be_bytes()[..2]).unwrap();
            client.write_all(&5u32.to_be_bytes()[2..]).unwrap();
            client.write_all(b"AB").unwrap();
            client.write_all(b"CDE").unwrap();
        });
        assert_eq!(
            receive_attested_frame(&server, peer, 5, Duration::from_secs(1)),
            Ok(b"ABCDE".to_vec())
        );
    });
    for size in [0u32, 6, u32::MAX] {
        let (mut client, server) = UnixStream::pair().unwrap();
        let peer = observe_kernel_peer(&server).unwrap();
        enable_writer_credentials(&server).unwrap();
        client.write_all(&size.to_be_bytes()).unwrap();
        assert_eq!(
            receive_attested_frame(&server, peer, 5, Duration::from_secs(1)),
            Err(IdentityDenied)
        );
    }
}

#[test]
fn frame_rejects_missing_credentials_truncation_and_stalled_writer() {
    use jdc_authority_service::linux_message_origin::receive_attested_frame;
    for mode in 0..3 {
        let (mut client, server) = UnixStream::pair().unwrap();
        let peer = observe_kernel_peer(&server).unwrap();
        if mode != 0 {
            enable_writer_credentials(&server).unwrap();
        }
        client.write_all(&4u32.to_be_bytes()).unwrap();
        client.write_all(b"AB").unwrap();
        if mode == 1 {
            client.shutdown(std::net::Shutdown::Write).unwrap();
        }
        let start = std::time::Instant::now();
        assert_eq!(
            receive_attested_frame(&server, peer, 4, Duration::from_millis(50)),
            Err(IdentityDenied)
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}

#[test]
fn unexpected_kernel_pidfd_is_denied_without_leaking_a_descriptor() {
    // Run in a separate test process so unrelated parallel tests cannot
    // affect /proc/self/fd observations.
    const CHILD: &str = "JDC_T011_PIDFD_CLOSURE_CHILD";
    if env::var_os(CHILD).is_none() {
        let status = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "unexpected_kernel_pidfd_is_denied_without_leaking_a_descriptor",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let (mut client, server) = UnixStream::pair().unwrap();
    let peer = observe_kernel_peer(&server).unwrap();
    enable_writer_credentials(&server).unwrap();
    // Linux UAPI asm-generic/socket.h (SO_PASSPIDFD); libc 0.2.190
    // does not expose this constant on the supported Linux target.
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            server.as_raw_fd(),
            libc::SOL_SOCKET,
            76,
            (&enabled as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result != 0 {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOPROTOOPT)
        );
        eprintln!("SO_PASSPIDFD_UNSUPPORTED_KERNEL");
        return;
    }
    let count_pidfds = || {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read_link(entry.path()).ok())
            .filter(|target| target.to_str() == Some("anon_inode:[pidfd]"))
            .count()
    };
    let before = count_pidfds();
    client.write_all(b"R").unwrap();
    assert_eq!(receive_attested_byte(&server, peer), Err(IdentityDenied));
    assert_eq!(
        count_pidfds(),
        before,
        "denied ancillary data leaked a kernel pidfd"
    );
    eprintln!("T011_LINUX_PIDFD_DENIED_AND_CLOSED_NONRELEASE");
}
