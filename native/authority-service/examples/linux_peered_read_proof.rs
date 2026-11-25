//! T011 non-shipping, GitHub-runner-only kernel/IPC/read integration proof.
//! NOT a trusted policy source, IPC protocol, installation or MCP authority.
//! A root-owned CI issuer starts one fixed, non-dumpable client under the
//! OS-managed jdc-mcp-client principal and sends its live pidfd to the
//! separately authenticated authority account. This is a disposable
//! OS-process proof, NOT a shipping original desktop MCP host, managed
//! installation, or durable policy and revocation mechanism.
#[cfg(target_os = "linux")]
mod proof {
    use jdc_authority_service::{
        linux_message_origin::enable_writer_credentials,
        linux_peer::observe_kernel_peer,
        linux_read_disclosure::read_attested_regular_into_socket,
        peer_policy::{verify_distinct_peer, DedicatedAccount},
        policy_epoch::PolicyFence,
        verify_service_identity,
    };
    use std::{
        env,
        fs::{self, File},
        io::{Read, Write},
        mem::{size_of, zeroed, MaybeUninit},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{
                fs::{MetadataExt, PermissionsExt},
                net::{UnixListener, UnixStream},
                process::CommandExt,
            },
        },
        path::Path,
        process::{Command, ExitCode},
        ptr,
        time::{Duration, Instant},
    };

    const AUTHORIZED_CONTENT: &[u8] = b"SERVICE_DOMAIN_BYTES";
    fn io<T>(result: std::io::Result<T>) -> Result<T, &'static str> {
        result.map_err(|_| "E_PEER_PROOF_IO")
    }

    // Resolve a fixture-only external principal through the OS, never client text.
    fn fixture_client() -> Result<DedicatedAccount, &'static str> {
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

    // Root-only CI issuer: the child is created under the OS-managed client
    // account, never by the interactive MCP user or a user-writable launcher.
    fn send_attestation(channel: &UnixStream, pid: u32, pidfd: i32) -> Result<(), &'static str> {
        let mut payload = pid.to_be_bytes();
        let mut vector = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let control_size = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;
        let mut ancillary = [0usize; 8];
        if control_size > size_of::<[usize; 8]>() {
            return Err("E_PEER_PROOF_ISSUER_CONTROL_CAPACITY");
        }
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = control_size;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() {
                return Err("E_PEER_PROOF_ISSUER_HEADER");
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;
            ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), pidfd);
            if libc::sendmsg(channel.as_raw_fd(), &message, libc::MSG_NOSIGNAL) != 4 {
                return Err("E_PEER_PROOF_ISSUER_SEND");
            }
        }
        Ok(())
    }

    fn issue(
        issuer_socket: &Path,
        client_socket: &Path,
        sdk: Option<(&Path, &Path)>,
    ) -> Result<(), &'static str> {
        if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
            return Err("E_PEER_PROOF_ISSUER_NOT_ROOT");
        }
        let approved = fixture_client()?;
        let mut command = if let Some((node, script)) = sdk {
            if env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
                || env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
            {
                return Err("E_PEER_PROOF_ISSUED_SDK_RUNNER_REQUIRED");
            }
            let mut issued = Command::new(node);
            issued.arg(script).arg(client_socket);
            issued.env("GITHUB_ACTIONS", "true");
            issued.env("RUNNER_ENVIRONMENT", "github-hosted");
            issued
        } else {
            let mut issued = Command::new(io(env::current_exe())?);
            issued.arg("allow").arg(client_socket);
            issued
        };
        command.uid(approved.uid).gid(approved.gid);
        // Rust CommandExt::uid already clears inherited supplementary
        // groups via setgroups(0, NULL) before changing UID. No pre_exec
        // callback is needed or permitted for this credential transition.
        let mut child = io(command.spawn())?;
        let outcome = (|| {
            let raw =
                unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0u32) };
            if raw < 0 || raw > i64::from(i32::MAX) {
                return Err("E_PEER_PROOF_ISSUER_PIDFD");
            }
            let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
            let channel = io(UnixStream::connect(issuer_socket))?;
            io(channel.set_write_timeout(Some(Duration::from_secs(3))))?;
            send_attestation(&channel, child.id(), pidfd.as_raw_fd())?;
            if !io(child.wait())?.success() {
                return Err("E_PEER_PROOF_ISSUED_CLIENT_FAILED");
            }
            eprintln!("T011_LINUX_ROOT_ISSUED_CLIENT_EXACT_BYTES_NONRELEASE");
            Ok(())
        })();
        if outcome.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        outcome
    }

    fn receive_attestation(listener: &UnixListener) -> Result<(u32, OwnedFd), &'static str> {
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
        if unsafe { libc::recvmsg(channel.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) } != 4
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        {
            return Err("E_PEER_PROOF_ISSUER_RECV");
        }
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() {
            return Err("E_PEER_PROOF_ISSUER_NO_PIDFD");
        }
        let checked = unsafe { &*header };
        if checked.cmsg_level != libc::SOL_SOCKET
            || checked.cmsg_type != libc::SCM_RIGHTS
            || checked.cmsg_len as usize
                != unsafe { libc::CMSG_LEN(size_of::<libc::c_int>() as u32) } as usize
            || !unsafe { libc::CMSG_NXTHDR(&message, header) }.is_null()
        {
            return Err("E_PEER_PROOF_ISSUER_DESCRIPTOR_FORMAT");
        }
        let raw = unsafe { ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>()) };
        if raw < 0 {
            return Err("E_PEER_PROOF_ISSUER_INVALID_DESCRIPTOR");
        }
        let pinned = unsafe { OwnedFd::from_raw_fd(raw) };
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

    fn serve(root: &Path, socket: &Path, issuer_socket: &Path) -> Result<(), &'static str> {
        // An ordinary interactive process cannot impersonate this service.
        verify_service_identity().map_err(|_| "E_PEER_PROOF_SERVICE_IDENTITY")?;
        let root_fd = io(File::open(root))?;
        let metadata = io(root_fd.metadata())?;
        let service_uid = unsafe { libc::geteuid() };
        let service_gid = unsafe { libc::getegid() };
        let service_pid = unsafe { libc::getpid() };
        if !metadata.is_dir()
            || metadata.uid() != service_uid
            || metadata.gid() != service_gid
            || metadata.mode() & 0o777 != 0o700
        {
            return Err("E_PEER_PROOF_ROOT_CUSTODY");
        }
        let approved_client = fixture_client()?;
        if approved_client.uid == service_uid || approved_client.gid == service_gid {
            return Err("E_PEER_PROOF_IDENTITIES_NOT_DISTINCT");
        }
        let listener = io(UnixListener::bind(socket))?;
        // Intentionally allow an untrusted caller to reach SO_PEERCRED.
        // Socket permissions alone are NOT the authentication proof.
        io(fs::set_permissions(
            socket,
            fs::Permissions::from_mode(0o777),
        ))?;
        // The issuer socket is owned by the distinct service principal and
        // writable only by it or root. A same-interactive-UID caller cannot
        // send an attested client PID or obtain the held pidfd.
        let issuer_listener = io(UnixListener::bind(issuer_socket))?;
        io(fs::set_permissions(
            issuer_socket,
            fs::Permissions::from_mode(0o600),
        ))?;
        let (approved_pid, pinned) = receive_attestation(&issuer_listener)?;
        // Fixed disposable policy, not a durable installed-policy source.
        let policy = PolicyFence::new(1).map_err(|_| "E_PEER_PROOF_POLICY")?;
        let deadline = Instant::now() + Duration::from_secs(12);
        let mut foreign_denied = false;
        let mut same_uid_denied = false;
        let mut authentic_read = false;
        while !foreign_denied || !same_uid_denied || !authentic_read {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout = i32::try_from(remaining.as_millis().min(12_000))
                .map_err(|_| "E_PEER_PROOF_TIMEOUT_OVERFLOW")?;
            if timeout == 0 {
                return Err("E_PEER_PROOF_ACCEPT_TIMEOUT");
            }
            let mut ready = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut ready, 1, timeout) } != 1
                || ready.revents & libc::POLLIN == 0
            {
                return Err("E_PEER_PROOF_ACCEPT_TIMEOUT");
            }
            let (mut conn, _) = io(listener.accept())?;
            io(conn.set_read_timeout(Some(Duration::from_secs(3))))?;
            io(conn.set_write_timeout(Some(Duration::from_secs(3))))?;
            let peer = observe_kernel_peer(&conn).map_err(|_| "E_PEER_PROOF_KERNEL_CREDENTIALS")?;
            let uid_valid =
                verify_distinct_peer(peer, approved_client, service_uid, service_gid, service_pid)
                    .is_ok();
            if !uid_valid || peer.pid as u32 != approved_pid {
                if uid_valid {
                    if same_uid_denied {
                        return Err("E_PEER_PROOF_REPEATED_SAME_UID");
                    }
                    same_uid_denied = true;
                    eprintln!("T011_LINUX_SAME_UID_FOREIGN_CLIENT_DENIED");
                } else {
                    if foreign_denied {
                        return Err("E_PEER_PROOF_REPEATED_FOREIGN_CLIENT");
                    }
                    foreign_denied = true;
                    eprintln!("T011_LINUX_FOREIGN_UID_DENIED");
                }
                io(conn.write_all(b"D"))?;
                continue;
            }
            if authentic_read {
                return Err("E_PEER_PROOF_REPLAY_CLIENT");
            }
            let mut state = libc::pollfd {
                fd: pinned.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut state, 1, 0) } != 0 {
                return Err("E_PEER_PROOF_ISSUED_PROCESS_EXITED");
            }
            enable_writer_credentials(&conn).map_err(|_| "E_PEER_PROOF_PASSCRED_UNAVAILABLE")?;
            // The handshake ensures that Linux installs SCM_CREDENTIALS before
            // the only request byte can be sent by the original process.
            io(conn.write_all(b"C"))?;
            // The client supplies NO pathname, root, epoch, PID, UID or authority.
            // The issuer-approved peer receives only the service-selected file.
            // The independent native/SDK client still checks the exact bytes.
            let ticket = policy.issue_read().map_err(|_| "E_PEER_PROOF_POLICY")?;
            read_attested_regular_into_socket(
                &policy,
                &ticket,
                &conn,
                peer,
                &root_fd,
                Path::new("service.bin"),
                Duration::from_secs(3),
            )
            .map_err(|_| "E_PEER_PROOF_NATIVE_READ_DENIED")?;
            policy.revoke().map_err(|_| "E_PEER_PROOF_POLICY")?;
            authentic_read = true;
        }
        eprintln!("T011_LINUX_ROOT_ISSUED_PEER_BOUND_READ_PASS_NONRELEASE");
        Ok(())
    }

    fn request(
        socket: &Path,
        should_allow: bool,
        untrusted_same_uid_origin: bool,
    ) -> Result<(), &'static str> {
        if untrusted_same_uid_origin && should_allow {
            return Err("E_PEER_PROOF_UNTRUSTED_MUST_BE_DENIED");
        }
        if should_allow {
            // A second same-UID process must not attach to this managed
            // fixture using ptrace/proc-mem while the issued client is live.
            if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
                || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
            {
                return Err("E_PEER_PROOF_CLIENT_DUMPABLE");
            }
        }
        let mut conn = io(UnixStream::connect(socket))?;
        io(conn.set_read_timeout(Some(Duration::from_secs(3))))?;
        io(conn.set_write_timeout(Some(Duration::from_secs(3))))?;
        // Both unauthorized principals request admission to the one-read
        // protocol by connecting. Only a protected issuer's original process
        // may receive the 'C' challenge and send 'R'. Sending 'R' before this
        // decision leaves unread data in a denied socket and can cause Linux
        // to reset it, masking an actual denial. Verify the exact 'D' reply
        // and absence of protected bytes rather than accepting a transport
        // reset as a security verdict.
        let mut decision = [0u8; 1];
        conn.read_exact(&mut decision)
            .map_err(|_| "E_PEER_PROOF_ADMISSION_DECISION_UNREADABLE")?;
        if should_allow {
            if decision != *b"C" {
                return Err("E_PEER_PROOF_LEGITIMATE_HANDSHAKE_DENIED");
            }
            io(conn.write_all(b"R"))?;
            io(conn.read_exact(&mut decision))?;
        }
        if !should_allow {
            if decision != *b"D" {
                return Err("E_PEER_PROOF_FOREIGN_CLIENT_ACCEPTED");
            }
            let mut extra = [0_u8; 1];
            if io(conn.read(&mut extra))? != 0 {
                return Err("E_PEER_PROOF_DENIED_BYTES_LEAKED");
            }
            if untrusted_same_uid_origin {
                eprintln!("T011_LINUX_SAME_UID_UNTRUSTED_CLIENT_NO_BYTES");
            } else {
                eprintln!("T011_LINUX_FOREIGN_PEER_DENIED_NO_BYTES");
            }
            return Ok(());
        }
        if decision != *b"A" {
            return Err("E_PEER_PROOF_LEGITIMATE_CLIENT_DENIED");
        }
        let mut size = [0_u8; 4];
        io(conn.read_exact(&mut size))?;
        let count = u32::from_be_bytes(size) as usize;
        if count != AUTHORIZED_CONTENT.len() {
            return Err("E_PEER_PROOF_WRONG_RESPONSE_SIZE");
        }
        let mut payload = vec![0_u8; count];
        io(conn.read_exact(&mut payload))?;
        if payload != AUTHORIZED_CONTENT {
            return Err("E_PEER_PROOF_BAD_RESPONSE");
        }
        let mut extra = [0_u8; 1];
        if io(conn.read(&mut extra))? != 0 {
            return Err("E_PEER_PROOF_TRAILING_RESPONSE_BYTES");
        }
        eprintln!("T011_LINUX_LEGITIMATE_CLIENT_RECEIVED_BOUND_BYTES");
        Ok(())
    }

    pub fn main() -> ExitCode {
        let mut args = env::args_os().skip(1);
        let result = match (
            args.next(),
            args.next(),
            args.next(),
            args.next(),
            args.next(),
        ) {
            (Some(role), Some(root), Some(socket), Some(issuer), None) if role == "serve" => {
                serve(Path::new(&root), Path::new(&socket), Path::new(&issuer))
            }
            (Some(role), Some(issuer), Some(socket), None, None) if role == "issue" => {
                issue(Path::new(&issuer), Path::new(&socket), None)
            }
            (Some(role), Some(issuer), Some(socket), Some(node), Some(script))
                if role == "issue-sdk" =>
            {
                issue(
                    Path::new(&issuer),
                    Path::new(&socket),
                    Some((Path::new(&node), Path::new(&script))),
                )
            }
            (Some(role), Some(socket), None, None, None) if role == "allow" => {
                request(Path::new(&socket), true, false)
            }
            (Some(role), Some(socket), None, None, None) if role == "impersonate" => {
                request(Path::new(&socket), false, true)
            }
            (Some(role), Some(socket), None, None, None) if role == "deny" => {
                request(Path::new(&socket), false, false)
            }
            _ => Err("E_PEER_PROOF_ARGUMENTS"),
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        }
    }
}
#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    proof::main()
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("E_PEER_PROOF_LINUX_ONLY");
    std::process::ExitCode::FAILURE
}
