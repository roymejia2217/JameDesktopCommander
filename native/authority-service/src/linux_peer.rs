//! T011-C4: kernel-issued Unix-socket peer observation, NON-AUTHORIZING.
//!
//! SO_PEERCRED is an identity observation made by the Linux kernel at socket
//! connection time. It is NOT a durable peer credential, a request signature,
//! a protected policy decision or a filesystem capability. Descriptor passing
//! and subsequent principal transitions require independent protocol review.
//! No listener or production request route invokes this module.

use crate::{peer_policy::KernelPeer, IdentityDenied};
use std::{mem, os::fd::AsRawFd, os::unix::net::UnixStream};

/// Returns only the credentials attached by the kernel to this Unix socket.
/// A caller MUST NOT promote this result to authorization without separately
/// established protected client identity, verified OS peer and policy epoch.
#[allow(dead_code)]
pub(crate) fn observe_kernel_peer(stream: &UnixStream) -> Result<KernelPeer, IdentityDenied> {
    let mut raw = mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            raw.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if status != 0 || length as usize != mem::size_of::<libc::ucred>() {
        return Err(IdentityDenied);
    }
    let credential = unsafe { raw.assume_init() };
    if credential.pid <= 0 {
        return Err(IdentityDenied);
    }
    Ok(KernelPeer {
        pid: credential.pid,
        uid: credential.uid,
        gid: credential.gid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_policy::{verify_distinct_peer, DedicatedAccount};
    use std::{
        env, fs,
        io::{Read, Write},
        os::unix::net::UnixListener,
        path::PathBuf,
        process::Command,
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    struct OwnedSocketPath(PathBuf);
    impl Drop for OwnedSocketPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn socket_pair_uses_kernel_credentials_not_client_provided_text() {
        let (mut client, mut server) = UnixStream::pair().expect("local pair");
        let observed = observe_kernel_peer(&server).expect("kernel peer credential");
        assert_eq!(observed.pid, unsafe { libc::getpid() });
        assert_eq!(observed.uid, unsafe { libc::geteuid() });
        assert_eq!(observed.gid, unsafe { libc::getegid() });

        client
            .write_all(b"pid=1 uid=0 gid=0")
            .expect("spoofed bytes");
        let mut received = [0u8; 17];
        server.read_exact(&mut received).expect("payload");
        assert_eq!(&received, b"pid=1 uid=0 gid=0");
        assert_eq!(observe_kernel_peer(&server), Ok(observed));
    }

    #[test]
    fn subprocess_fixture_connects_to_parent_owned_unix_socket() {
        let Ok(path) = env::var("JDC_PEER_TEST_SOCKET") else {
            return;
        };
        let mut socket = UnixStream::connect(path).expect("connect to test-owned listener");
        socket.write_all(&[0x51]).expect("send test marker");
    }

    #[test]
    fn separate_client_process_is_observed_and_same_principal_denied() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("monotonic test-clock epoch");
        let path = env::temp_dir().join(format!(
            "jdc-peer-{}-{}.sock",
            std::process::id(),
            now.as_nanos()
        ));
        let listener = UnixListener::bind(&path).expect("unique owned listener");
        let _socket_cleanup = OwnedSocketPath(path.clone());
        listener
            .set_nonblocking(true)
            .expect("bounded accept is mandatory");

        let mut child = Command::new(env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "linux_peer::tests::subprocess_fixture_connects_to_parent_owned_unix_socket",
            ])
            .env("JDC_PEER_TEST_SOCKET", &path)
            .spawn()
            .expect("spawn real child process");

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut accepted = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(ref error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("peer fixture unavailable within bound: {error}");
                }
            }
        };

        let observed = observe_kernel_peer(&accepted).expect("actual Linux peer");
        assert_eq!(observed.pid as u32, child.id());
        assert_eq!(observed.uid, unsafe { libc::geteuid() });
        assert_eq!(observed.gid, unsafe { libc::getegid() });
        let mut marker = [0u8; 1];
        accepted
            .read_exact(&mut marker)
            .expect("child connected and sent marker");
        assert_eq!(marker, [0x51]);
        assert!(child.wait().expect("child exit").success());

        // A process running under the same principal as the authority is
        // NOT an independently authenticated, separately administered peer.
        assert_eq!(
            verify_distinct_peer(
                observed,
                DedicatedAccount {
                    uid: observed.uid,
                    gid: observed.gid
                },
                observed.uid,
                unsafe { libc::getpid() },
            ),
            Err(IdentityDenied)
        );
    }
}
