//! Shared, nonshipping hosted issuer observation for the read and mutation proofs.
use super::{observe_kernel_peer, DedicatedAccount};
use std::{
    fs,
    mem::{size_of, zeroed, MaybeUninit},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixListener,
    },
    ptr,
    time::Duration,
};
fn io<T>(result: std::io::Result<T>) -> Result<T, &'static str> {
    result.map_err(|_| "E_PEER_PROOF_IO")
}

// Resolve a fixture-only external principal through the OS, never client text.
pub(super) fn fixture_client() -> Result<DedicatedAccount, &'static str> {
    let mut passwd = MaybeUninit::<libc::passwd>::zeroed();
    let mut found = ptr::null_mut();
    let mut scratch = [0 as libc::c_char; 16_384];
    let code = unsafe {
        libc::getpwnam_r(
            c"jdc-mcp-client".as_ptr(),
            passwd.as_mut_ptr(),
            scratch.as_mut_ptr(),
            scratch.len(),
            &mut found,
        )
    };
    if code != 0 || found.is_null() {
        return Err("E_PEER_PROOF_CLIENT_ACCOUNT_MISSING");
    }
    let passwd = unsafe { passwd.assume_init() };
    if passwd.pw_uid == 0 || passwd.pw_gid == 0 {
        return Err("E_PEER_PROOF_CLIENT_ACCOUNT_ROOT");
    }
    Ok(DedicatedAccount {
        uid: passwd.pw_uid,
        gid: passwd.pw_gid,
    })
}

pub(super) fn receive_attestation(listener: &UnixListener) -> Result<(u32, OwnedFd), &'static str> {
    let mut ready = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut ready, 1, 5_000) } != 1 || ready.revents & libc::POLLIN == 0 {
        return Err("E_PEER_PROOF_ISSUER_TIMEOUT");
    }
    let (channel, _) = io(listener.accept())?;
    let issuer = observe_kernel_peer(&channel).map_err(|_| "E_PEER_PROOF_ISSUER_IDENTITY")?;
    if issuer.pid <= 0 || issuer.uid != 0 || issuer.gid != 0 {
        return Err("E_PEER_PROOF_UNPROTECTED_ISSUER");
    }
    io(channel.set_read_timeout(Some(Duration::from_secs(3))))?;
    receive_attestation_payload(&channel)
}

fn receive_attestation_payload(
    channel: &std::os::unix::net::UnixStream,
) -> Result<(u32, OwnedFd), &'static str> {
    let mut pid_bytes = [0u8; 4];
    let mut vector = libc::iovec {
        iov_base: pid_bytes.as_mut_ptr().cast(),
        iov_len: pid_bytes.len(),
    };
    let mut ancillary = [0usize; 8];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = size_of::<[usize; 8]>();
    let count = unsafe { libc::recvmsg(channel.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if count < 0 {
        return Err("E_PEER_PROOF_ISSUER_RECV");
    }
    // recvmsg may install descriptors even on a short/truncated message.
    // Adopt every delivered descriptor before checking the wire format.
    let mut received = Vec::<OwnedFd>::new();
    let mut valid = count == 4 && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    let mut rights_messages = 0;
    while !header.is_null() {
        let h = unsafe { &*header };
        let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
        let size = h.cmsg_len as usize;
        if size < minimum || size > message.msg_controllen {
            valid = false;
            break;
        }
        let bytes = size - minimum;
        if h.cmsg_level == libc::SOL_SOCKET && matches!(h.cmsg_type, libc::SCM_RIGHTS | 0x04) {
            if h.cmsg_type == libc::SCM_RIGHTS {
                rights_messages += 1;
            } else {
                valid = false;
            }
            if bytes != size_of::<libc::c_int>() {
                valid = false;
            }
            for index in 0..bytes / size_of::<libc::c_int>() {
                let fd = unsafe {
                    ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>().add(index))
                };
                if fd < 0 {
                    valid = false;
                } else {
                    received.push(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        } else {
            valid = false;
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if !valid || rights_messages != 1 || received.len() != 1 {
        return Err("E_PEER_PROOF_ISSUER_DESCRIPTOR_FORMAT");
    }
    let pinned = received.pop().unwrap();
    let client_pid = u32::from_be_bytes(pid_bytes);
    if client_pid == 0 {
        return Err("E_PEER_PROOF_ISSUER_INVALID_PID");
    }
    // pidfd is kernel-maintained; unlike a numeric PID its identity
    // survives process exit and prevents PID-reuse authorization.
    let info = io(fs::read_to_string(format!(
        "/proc/self/fdinfo/{}",
        pinned.as_raw_fd()
    )))?;
    let observed_pid = info
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|text| text.trim().parse::<u32>().ok());
    if observed_pid != Some(client_pid) {
        return Err("E_PEER_PROOF_ISSUER_PIDFD_MISMATCH");
    }
    let mut state = libc::pollfd {
        fd: pinned.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut state, 1, 0) } != 0 {
        return Err("E_PEER_PROOF_ISSUER_CLIENT_NOT_LIVE");
    }
    Ok((client_pid, pinned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::net::UnixStream};
    #[test]
    fn malformed_attestation_closes_every_installed_fd() {
        const CHILD: &str = "JDC_T011_ATTESTATION_FD_TEST";
        if std::env::var_os(CHILD).is_none() {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!(
                        "{}::malformed_attestation_closes_every_installed_fd",
                        module_path!().split_once("::").unwrap().1
                    )
                ])
                .env(CHILD, "1")
                .status()
                .unwrap()
                .success());
            return;
        }
        let (mut tx, rx) = UnixStream::pair().unwrap();
        let source = fs::File::open("/dev/null").unwrap();
        let count = || fs::read_dir("/proc/self/fd").unwrap().count();
        for (length, descriptors) in [(1usize, 1usize), (4, 2), (4, 40)] {
            let before = count();
            let mut payload = [0u8; 4];
            let mut vector = libc::iovec {
                iov_base: payload.as_mut_ptr().cast(),
                iov_len: length,
            };
            let mut control = [0usize; 128];
            let mut msg: libc::msghdr = unsafe { zeroed() };
            msg.msg_iov = &mut vector;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            let size = (descriptors * size_of::<i32>()) as u32;
            msg.msg_controllen = unsafe { libc::CMSG_SPACE(size) } as usize;
            unsafe {
                let h = libc::CMSG_FIRSTHDR(&msg);
                (*h).cmsg_level = libc::SOL_SOCKET;
                (*h).cmsg_type = libc::SCM_RIGHTS;
                (*h).cmsg_len = libc::CMSG_LEN(size) as _;
                for i in 0..descriptors {
                    ptr::write_unaligned(
                        libc::CMSG_DATA(h).cast::<i32>().add(i),
                        source.as_raw_fd(),
                    );
                }
                assert_eq!(libc::sendmsg(tx.as_raw_fd(), &msg, 0), length as isize);
            }
            assert!(receive_attestation_payload(&rx).is_err());
            assert_eq!(
                count(),
                before,
                "leak on {length} bytes/{descriptors} descriptors"
            );
        }
        tx.write_all(b"BAD!").unwrap();
        assert!(receive_attestation_payload(&rx).is_err());
    }
}
