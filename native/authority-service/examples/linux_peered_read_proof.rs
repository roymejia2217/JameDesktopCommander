//! T011 non-shipping, GitHub-runner-only kernel/IPC/read integration proof.
//! NOT a trusted policy source, IPC protocol, installation or MCP authority.
//! A root-owned CI issuer starts one fixed, non-dumpable client under the
//! OS-managed jdc-mcp-client principal and sends its live pidfd to the
//! separately authenticated authority account. This is a disposable
//! OS-process proof, NOT a shipping original desktop MCP host, managed
//! installation, or durable policy and revocation mechanism.
#[cfg(target_os = "linux")]
use jdc_authority_service::{linux_peer::observe_kernel_peer, peer_policy::DedicatedAccount};
#[cfg(target_os = "linux")]
#[path = "../src/linux_fixture_issuer.rs"]
mod fixture_issuer;
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
        ffi::CString,
        fs::{self, File},
        io::{Read, Write},
        mem::{size_of, zeroed},
        os::{
            fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, PermissionsExt},
                net::{UnixListener, UnixStream},
                process::CommandExt,
            },
        },
        path::{Path, PathBuf},
        process::{Command, ExitCode, Stdio},
        ptr,
        time::{Duration, Instant},
    };

    const AUTHORIZED_CONTENT: &[u8] = b"SERVICE_DOMAIN_BYTES";
    fn io<T>(result: std::io::Result<T>) -> Result<T, &'static str> {
        result.map_err(|_| "E_PEER_PROOF_IO")
    }

    use super::fixture_issuer::{
        fixture_account, fixture_client, receive_attestation, receive_fixture_descriptor,
        verify_live_pidfd,
    };

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

    // Observe only the fixed fixture processes. A permission error is the
    // expected negative result; missing/dead targets are not evidence.
    fn inspection_denied<T>(result: std::io::Result<T>) -> Result<(), &'static str> {
        match result {
            Err(error)
                if matches!(error.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM)) =>
            {
                Ok(())
            }
            _ => Err("E_PEER_SDK_INSPECTION_NOT_DENIED"),
        }
    }

    fn fixture_pid(pid: u32, account: DedicatedAccount) -> Result<(), &'static str> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err("E_PEER_SDK_INSPECTION_PID");
        }
        let status = io(fs::read_to_string(format!("/proc/{pid}/status")))?;
        for (key, expected) in [("Uid:", account.uid), ("Gid:", account.gid)] {
            let line = status
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .ok_or("E_PEER_SDK_INSPECTION_IDENTITY")?;
            let ids: Vec<_> = line.split_whitespace().collect();
            if ids.len() != 4 || ids.iter().any(|id| id.parse::<u32>() != Ok(expected)) {
                return Err("E_PEER_SDK_INSPECTION_IDENTITY");
            }
        }
        if unsafe { libc::kill(pid as libc::pid_t, 0) } != 0 {
            return Err("E_PEER_SDK_INSPECTION_TARGET_NOT_LIVE");
        }
        Ok(())
    }

    fn inspect_same_uid(pid: u32, state: Option<&Path>) -> Result<(), &'static str> {
        let account = fixture_client()?;
        if env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
            || env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
            || unsafe { libc::getuid() } != account.uid
            || unsafe { libc::geteuid() } != account.uid
            || unsafe { libc::getgid() } != account.gid
            || unsafe { libc::getegid() } != account.gid
        {
            return Err("E_PEER_SDK_INSPECTION_PRINCIPAL");
        }
        // The adversary must actually be outside AppArmor confinement.
        // A constrained inspector could otherwise produce a false denial.
        let label = io(fs::read_to_string("/proc/self/attr/apparmor/current"))?;
        if label.trim_end_matches('\n') != "unconfined" {
            return Err("E_PEER_SDK_INSPECTOR_CONFINED");
        }
        fixture_pid(pid, account)?;
        let proc = format!("/proc/{pid}");
        if let Some(state) = state {
            // The same UID must not traverse the host mountpoint or enter
            // the issued client's private state through procfs.
            let private = PathBuf::from(format!("{proc}/root")).join(
                state
                    .strip_prefix("/")
                    .map_err(|_| "E_PEER_SDK_STATE_PATH")?,
            );
            for target in [
                state.join("sdk-state-proof"),
                private.join("sdk-state-proof"),
            ] {
                inspection_denied(File::open(&target))?;
                inspection_denied(fs::OpenOptions::new().write(true).open(&target))?;
            }
            inspection_denied(fs::read_link(format!("{proc}/root")))?;
            inspection_denied(fs::read_link(format!("{proc}/ns/mnt")))?;
            inspection_denied(fs::read_link(format!("{proc}/exe")))?;
            inspection_denied(fs::read_link(format!("{proc}/fd/0")))?;
            inspection_denied(File::open(format!("{proc}/maps")))?;
            inspection_denied(File::open(format!("{proc}/mem")))?;
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) };
            if raw < 0 || raw > i64::from(i32::MAX) {
                return Err("E_PEER_SDK_INSPECTION_PIDFD");
            }
            let pin = unsafe { OwnedFd::from_raw_fd(raw as i32) };
            let duplicate =
                unsafe { libc::syscall(libc::SYS_pidfd_getfd, pin.as_raw_fd(), 0i32, 0u32) };
            if duplicate >= 0 {
                if duplicate <= i64::from(i32::MAX) {
                    drop(unsafe { OwnedFd::from_raw_fd(duplicate as i32) });
                }
                return Err("E_PEER_SDK_DESCRIPTOR_DUPLICATED");
            }
            inspection_denied::<()>(Err(std::io::Error::last_os_error()))?;
        } else {
            // Positive READ-mode controls distinguish actual confinement
            // from a broken procfs, mismatched identity or missing target.
            io(fs::read_link(format!("{proc}/exe")))?;
            if io(fs::read_link(format!("{proc}/fd/0")))? != Path::new("/dev/null") {
                return Err("E_PEER_SDK_INSPECTION_CONTROL_FD");
            }
            io(File::open(format!("{proc}/maps")))?;
            io(fs::read_link(format!("{proc}/root")))?;
            io(fs::read_link(format!("{proc}/ns/mnt")))?;
            // A real unconfined same-UID process can traverse the ordinary
            // target's procfs root, not merely read the symlink.
            io(fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("{proc}/root/dev/null")))?;
        }
        fixture_pid(pid, account)
    }

    fn run_inspector(
        account: DedicatedAccount,
        pid: u32,
        state: Option<&Path>,
    ) -> Result<(), &'static str> {
        let mut command = Command::new(io(env::current_exe())?);
        command
            .arg(if state.is_some() {
                "inspect-protected"
            } else {
                "inspect-control"
            })
            .arg(pid.to_string());
        if let Some(state) = state {
            command.arg(state);
        }
        let status = io(command
            .env_clear()
            .env("GITHUB_ACTIONS", "true")
            .env("RUNNER_ENVIRONMENT", "github-hosted")
            .uid(account.uid)
            .gid(account.gid)
            .stdin(std::process::Stdio::null())
            .status())?;
        if !status.success() {
            return Err("E_PEER_SDK_INSPECTION_FAILED");
        }
        Ok(())
    }

    // Linux UAPI: include/uapi/linux/nsfs.h, _IO(0xb7, 2/4).
    const NS_GET_USERNS: libc::c_ulong = 0xb701;
    const NS_GET_PARENT: libc::c_ulong = 0xb702;
    const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
    const NS_GET_OWNER_UID: libc::c_ulong = 0xb704;

    fn same_namespace(left: &File, right: &File) -> Result<bool, &'static str> {
        let left = io(left.metadata())?;
        let right = io(right.metadata())?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }

    fn sdk_namespace(pid: u32) -> Result<File, &'static str> {
        let ns = io(File::open(format!("/proc/{pid}/ns/user")))?;
        let issuer = io(File::open("/proc/self/ns/user"))?;
        let mut owner: libc::uid_t = u32::MAX;
        if same_namespace(&ns, &issuer)?
            || unsafe { libc::ioctl(ns.as_raw_fd(), NS_GET_OWNER_UID, &mut owner) } != 0
            || owner != 0
        {
            return Err("E_PEER_SDK_NAMESPACE_OWNER");
        }
        let raw = unsafe { libc::ioctl(ns.as_raw_fd(), NS_GET_PARENT) };
        if raw < 0 {
            return Err("E_PEER_SDK_NAMESPACE_PARENT");
        }
        let parent = unsafe { File::from_raw_fd(raw) };
        if !same_namespace(&parent, &issuer)? {
            return Err("E_PEER_SDK_NAMESPACE_PARENT");
        }
        Ok(ns)
    }

    // The host exposes only an empty root-owned mountpoint. Each authority
    // and its single issued SDK share a fresh root-owned mount namespace;
    // no ordinary same-UID process can enter it. Only that namespace sees
    // the client's private tmpfs.
    const STATE_PROOF: &[u8] = b"JDC_PRIVATE_SDK_STATE";

    fn sdk_state_path(node: &Path) -> Result<PathBuf, &'static str> {
        Ok(node
            .parent()
            .ok_or("E_PEER_SDK_STATE_PATH")?
            .join("client-state"))
    }

    fn verify_host_state(state: &Path) -> Result<fs::Metadata, &'static str> {
        let meta = io(fs::symlink_metadata(state))?;
        let parent = io(fs::symlink_metadata(
            state.parent().ok_or("E_PEER_SDK_STATE_PATH")?,
        ))?;
        if !meta.is_dir()
            || meta.uid() != 0
            || meta.gid() != 0
            || meta.mode() & 0o7777 != 0o700
            || meta.dev() != parent.dev()
            || io(fs::canonicalize(state))? != state
            || io(fs::read_dir(state))?.next().is_some()
        {
            return Err("E_PEER_SDK_HOST_STATE_CUSTODY");
        }
        Ok(meta)
    }

    fn mount_sdk_state(node: &Path, account: DedicatedAccount) -> Result<(), &'static str> {
        let state = sdk_state_path(node)?;
        verify_host_state(&state)?;
        let target =
            CString::new(state.as_os_str().as_bytes()).map_err(|_| "E_PEER_SDK_STATE_PATH")?;
        let options = CString::new(format!(
            "size=16m,nr_inodes=4096,mode=0700,uid={},gid={}",
            account.uid, account.gid
        ))
        .map_err(|_| "E_PEER_SDK_STATE_OPTIONS")?;
        // The launcher has already joined the exact authority namespace.
        // Preserve private propagation before mounting the per-client state.
        if unsafe {
            libc::mount(
                ptr::null(),
                c"/".as_ptr(),
                ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                ptr::null(),
            )
        } != 0
        {
            return Err("E_PEER_SDK_MOUNT_PROPAGATION");
        }
        if unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                target.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                options.as_ptr().cast(),
            )
        } != 0
        {
            return Err("E_PEER_SDK_STATE_MOUNT");
        }
        Ok(())
    }

    fn verify_private_mount_namespace(namespace: &File) -> Result<(), &'static str> {
        if unsafe { libc::ioctl(namespace.as_raw_fd(), NS_GET_NSTYPE) } != libc::CLONE_NEWNS {
            return Err("E_PEER_SDK_MOUNT_NAMESPACE_TYPE");
        }
        let issuer_mount = io(File::open("/proc/self/ns/mnt"))?;
        let issuer_user = io(File::open("/proc/self/ns/user"))?;
        if same_namespace(namespace, &issuer_mount)? {
            return Err("E_PEER_SDK_MOUNT_NAMESPACE_SHARED");
        }
        let raw = unsafe { libc::ioctl(namespace.as_raw_fd(), NS_GET_USERNS) };
        if raw < 0 {
            return Err("E_PEER_SDK_MOUNT_NAMESPACE_OWNER");
        }
        let owner = unsafe { File::from_raw_fd(raw) };
        if !same_namespace(&owner, &issuer_user)? {
            return Err("E_PEER_SDK_MOUNT_NAMESPACE_OWNER");
        }
        Ok(())
    }

    fn sdk_mount_namespace(pid: u32) -> Result<File, &'static str> {
        let namespace = io(File::open(format!("/proc/{pid}/ns/mnt")))?;
        verify_private_mount_namespace(&namespace)?;
        Ok(namespace)
    }

    struct SdkAuthority {
        pid: u32,
        pin: OwnedFd,
        namespace: File,
    }

    impl SdkAuthority {
        fn observe(channel: &UnixStream) -> Result<Self, &'static str> {
            let peer = observe_kernel_peer(channel).map_err(|_| "E_PEER_SDK_AUTHORITY_IDENTITY")?;
            let account = fixture_account(c"jdc-authority")?;
            if peer.uid != account.uid || peer.gid != account.gid || peer.pid <= 0 {
                return Err("E_PEER_SDK_AUTHORITY_IDENTITY");
            }
            // Pin the actual kernel socket peer, never reopen a nominated
            // PID as if it identified the same process. SO_PEERPIDFD is
            // available on the supported disposable Ubuntu runner kernel.
            let mut raw = -1i32;
            let mut len = size_of::<i32>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    channel.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERPIDFD,
                    (&mut raw as *mut i32).cast(),
                    &mut len,
                )
            } != 0
                || raw < 0
            {
                return Err("E_PEER_SDK_AUTHORITY_PIDFD");
            }
            let pin = unsafe { OwnedFd::from_raw_fd(raw) };
            if len as usize != size_of::<i32>() {
                return Err("E_PEER_SDK_AUTHORITY_PIDFD");
            }
            let pid = peer.pid as u32;
            verify_live_pidfd(&pin, pid)?;
            fixture_pid(pid, account)?;
            let namespace = sdk_mount_namespace(pid)?;
            verify_live_pidfd(&pin, pid)?;
            Ok(Self {
                pid,
                pin,
                namespace,
            })
        }

        fn verify(&self) -> Result<(), &'static str> {
            verify_live_pidfd(&self.pin, self.pid)?;
            if !same_namespace(&self.namespace, &sdk_mount_namespace(self.pid)?)? {
                return Err("E_PEER_SDK_AUTHORITY_NAMESPACE_CHANGED");
            }
            verify_live_pidfd(&self.pin, self.pid)
        }
    }

    fn verify_sdk_state(
        pid: u32,
        state: &Path,
        namespace: &File,
        account: DedicatedAccount,
    ) -> Result<(u64, u64, u64, u64), &'static str> {
        if !same_namespace(namespace, &sdk_mount_namespace(pid)?)? {
            return Err("E_PEER_SDK_MOUNT_NAMESPACE_CHANGED");
        }
        let host = verify_host_state(state)?;
        let private = PathBuf::from(format!("/proc/{pid}/root")).join(
            state
                .strip_prefix("/")
                .map_err(|_| "E_PEER_SDK_STATE_PATH")?,
        );
        let dir = io(File::open(&private))?;
        let meta = io(dir.metadata())?;
        let mut stat: libc::statfs = unsafe { zeroed() };
        let mut vfs: libc::statvfs = unsafe { zeroed() };
        let flags = libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
        if !meta.is_dir()
            || meta.uid() != account.uid
            || meta.gid() != account.gid
            || meta.mode() & 0o7777 != 0o700
            || meta.dev() == host.dev()
            || unsafe { libc::fstatfs(dir.as_raw_fd(), &mut stat) } != 0
            || stat.f_type != libc::TMPFS_MAGIC
            || unsafe { libc::fstatvfs(dir.as_raw_fd(), &mut vfs) } != 0
            || vfs.f_flag & flags != flags
        {
            return Err("E_PEER_SDK_PRIVATE_STATE_CUSTODY");
        }
        // The known SDK writes a fixed canary before signaling readiness.
        // Verify the actual file object and its exact non-secret bytes.
        let proof_path = private.join("sdk-state-proof");
        let proof = io(fs::symlink_metadata(&proof_path))?;
        if !proof.is_file()
            || proof.dev() != meta.dev()
            || proof.uid() != account.uid
            || proof.gid() != account.gid
            || proof.mode() & 0o7777 != 0o600
            || proof.nlink() != 1
            || proof.len() != STATE_PROOF.len() as u64
        {
            return Err("E_PEER_SDK_PRIVATE_STATE_PROOF");
        }
        let mut bytes = Vec::new();
        io(io(File::open(&proof_path))?
            .take(STATE_PROOF.len() as u64 + 1)
            .read_to_end(&mut bytes))?;
        if bytes != STATE_PROOF {
            return Err("E_PEER_SDK_PRIVATE_STATE_PROOF");
        }
        Ok((meta.dev(), meta.ino(), proof.dev(), proof.ino()))
    }

    fn exact_mapping(text: &str, id: u32) -> bool {
        id != 0
            && text
                .split_whitespace()
                .map(str::parse::<u32>)
                .eq([Ok(id), Ok(id), Ok(1)])
    }

    fn verify_sdk_namespace(
        pid: u32,
        expected: &File,
        account: DedicatedAccount,
    ) -> Result<(), &'static str> {
        if !same_namespace(expected, &sdk_namespace(pid)?)? {
            return Err("E_PEER_SDK_NAMESPACE_CHANGED");
        }
        for (key, id) in [("uid_map", account.uid), ("gid_map", account.gid)] {
            if !exact_mapping(&io(fs::read_to_string(format!("/proc/{pid}/{key}")))?, id) {
                return Err("E_PEER_SDK_NAMESPACE_MAP");
            }
        }
        Ok(())
    }

    fn readiness_byte(channel: &mut UnixStream, expected: u8) -> Result<(), &'static str> {
        let mut byte = [0u8; 1];
        io(channel.read_exact(&mut byte))?;
        if byte[0] != expected {
            return Err("E_PEER_SDK_STARTUP_PROTOCOL");
        }
        Ok(())
    }

    fn prepare_sdk_namespace(
        pid: u32,
        channel: &mut UnixStream,
        account: DedicatedAccount,
    ) -> Result<(File, File), &'static str> {
        readiness_byte(channel, b'N')?;
        let ns = sdk_namespace(pid)?;
        let mount_ns = sdk_mount_namespace(pid)?;
        for (key, id) in [("uid_map", account.uid), ("gid_map", account.gid)] {
            if id == 0 {
                return Err("E_PEER_SDK_NAMESPACE_MAP");
            }
            // Only the privileged parent writes the child's exact one-ID map.
            let mut file = io(fs::OpenOptions::new()
                .write(true)
                .open(format!("/proc/{pid}/{key}")))?;
            io(file.write_all(format!("{id} {id} 1\n").as_bytes()))?;
        }
        verify_sdk_namespace(pid, &ns, account)?;
        io(channel.write_all(b"M"))?;
        readiness_byte(channel, b'R')?;
        Ok((ns, mount_ns))
    }

    fn verify_sdk_credentials(pid: u32, account: DedicatedAccount) -> Result<(), &'static str> {
        fixture_pid(pid, account)?;
        let status = io(fs::read_to_string(format!("/proc/{pid}/status")))?;
        let field = |key: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .map(str::trim)
        };
        if field("Groups:") != Some("")
            || field("NoNewPrivs:") != Some("1")
            || ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
                .iter()
                .any(|key| {
                    field(key).and_then(|value| u64::from_str_radix(value, 16).ok()) != Some(0)
                })
        {
            return Err("E_PEER_SDK_NAMESPACE_CREDENTIALS");
        }
        Ok(())
    }

    // Run in a dedicated, freshly exec'd, single-threaded root fixture
    // process. No credential changes in a multi-threaded pre_exec callback.
    fn launch_sdk(
        node: &Path,
        script: &Path,
        socket: &Path,
        cancel: bool,
    ) -> Result<(), &'static str> {
        if unsafe { libc::getuid() } != 0
            || unsafe { libc::geteuid() } != 0
            || env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
            || env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
        {
            return Err("E_PEER_PROOF_ISSUER_NOT_ROOT");
        }
        let account = fixture_client()?;
        verify_sdk_image(node, account)?;
        let mut channel = UnixStream::from(io(std::io::stdin().as_fd().try_clone_to_owned())?);
        io(channel.set_read_timeout(Some(Duration::from_secs(5))))?;
        io(channel.set_write_timeout(Some(Duration::from_secs(5))))?;
        // The parent transfers the exact root-owned mount namespace FD of
        // the authenticated listening authority. No caller-selected PID or
        // path is used for setns, and no namespace FD survives Node exec.
        let (_, namespace) = receive_fixture_descriptor(&channel)?;
        let namespace = File::from(namespace);
        verify_private_mount_namespace(&namespace)?;
        if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNS) } != 0
            || !same_namespace(&namespace, &io(File::open("/proc/self/ns/mnt"))?)?
        {
            return Err("E_PEER_SDK_AUTHORITY_NAMESPACE_JOIN");
        }
        drop(namespace);
        mount_sdk_state(node, account)?;
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            return Err("E_PEER_SDK_NAMESPACE_CREATE");
        }
        io(channel.write_all(b"N"))?;
        readiness_byte(&mut channel, b'M')?;
        if unsafe { libc::setgroups(0, ptr::null()) } != 0
            || unsafe { libc::setresgid(account.gid, account.gid, account.gid) } != 0
            || unsafe { libc::setresuid(account.uid, account.uid, account.uid) } != 0
            || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) } != 0
        {
            return Err("E_PEER_SDK_NAMESPACE_CREDENTIALS");
        }
        // The original fd 0 is the private duplex readiness channel. The
        // duplicate is closed before exec; no additional handle is inherited.
        drop(channel);
        let mut command = Command::new(node);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GITHUB_ACTIONS", "true")
            .env("RUNNER_ENVIRONMENT", "github-hosted")
            .arg(script)
            .arg(socket);
        if cancel {
            command.arg("--hosted-cancel-before-commit");
        }
        let _error = command.exec();
        Err("E_PEER_SDK_NAMESPACE_EXEC")
    }

    fn verify_sdk_process_custody(
        node: &Path,
        pid: u32,
        pin: &OwnedFd,
        namespace: &File,
        mount_namespace: &File,
        account: DedicatedAccount,
    ) -> Result<(), &'static str> {
        let live = || {
            let mut state = libc::pollfd {
                fd: pin.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut state, 1, 0) } != 0 {
                return Err("E_PEER_SDK_INSPECTION_TARGET_EXITED");
            }
            Ok(())
        };
        let label = || {
            let mut value = String::new();
            io(File::open(format!("/proc/{pid}/attr/apparmor/current")))?
                .take(512)
                .read_to_string(&mut value)
                .map_err(|_| "E_PEER_SDK_PROFILE_UNVERIFIABLE")?;
            if value.trim_end_matches('\n') != format!("{} (enforce)", node.display()) {
                return Err("E_PEER_SDK_PROFILE_NOT_ENFORCING");
            }
            Ok(())
        };
        live()?;
        verify_sdk_namespace(pid, namespace, account)?;
        verify_sdk_credentials(pid, account)?;
        if io(fs::read_link(format!("/proc/{pid}/exe")))? != node {
            return Err("E_PEER_SDK_NAMESPACE_EXEC");
        }
        label()?;
        let state = sdk_state_path(node)?;
        let initial = verify_sdk_state(pid, &state, mount_namespace, account)?;
        let mut control = io(Command::new("/usr/bin/sleep")
            .arg("30")
            .env_clear()
            .uid(account.uid)
            .gid(account.gid)
            .stdin(std::process::Stdio::null())
            .spawn())?;
        let observed = run_inspector(account, control.id(), None);
        let stopped = control.kill();
        let reaped = control.wait();
        io(stopped)?;
        io(reaped)?;
        observed?;
        run_inspector(account, pid, Some(&state))?;
        live()?;
        if initial != verify_sdk_state(pid, &state, mount_namespace, account)? {
            return Err("E_PEER_SDK_STATE_IDENTITY_CHANGED");
        }
        eprintln!("T011_LINUX_SDK_PRIVATE_STATE_PASS_NONRELEASE");
        verify_sdk_namespace(pid, namespace, account)?;
        verify_sdk_credentials(pid, account)?;
        label()?;
        eprintln!("T011_LINUX_SDK_POST_EXEC_CUSTODY_PASS_NONRELEASE");
        Ok(())
    }

    fn verify_sdk_image(node: &Path, account: DedicatedAccount) -> Result<(), &'static str> {
        let parent = node.parent().ok_or("E_PEER_SDK_IMAGE_CUSTODY")?;
        let name = parent
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("jdc-t011-storage."))
            .ok_or("E_PEER_SDK_IMAGE_CUSTODY")?;
        if parent.parent() != Some(Path::new("/tmp"))
            || name.len() != 8
            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || node.file_name().and_then(|name| name.to_str()) != Some("sdk-node")
            || io(fs::canonicalize(node))? != node
        {
            return Err("E_PEER_SDK_IMAGE_CUSTODY");
        }
        let dir = io(fs::symlink_metadata(parent))?;
        let image = io(fs::symlink_metadata(node))?;
        if !dir.is_dir()
            || dir.uid() != 0
            || dir.gid() != 0
            || dir.mode() & 0o7777 != 0o711
            || !image.is_file()
            || image.uid() != 0
            || image.gid() != account.gid
            || image.mode() & 0o7777 != 0o550
            || image.nlink() != 1
        {
            return Err("E_PEER_SDK_IMAGE_CUSTODY");
        }
        Ok(())
    }

    fn issue(
        issuer_socket: &Path,
        client_socket: &Path,
        sdk: Option<(&Path, &Path, bool)>,
    ) -> Result<(), &'static str> {
        if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
            return Err("E_PEER_PROOF_ISSUER_NOT_ROOT");
        }
        let approved = fixture_client()?;
        let mut readiness = None;
        let mut sdk_authority = None;
        let mut sdk_channel = None;
        let mut command = if let Some((node, script, cancel_before_commit)) = sdk {
            if env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
                || env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
            {
                return Err("E_PEER_PROOF_ISSUED_SDK_RUNNER_REQUIRED");
            }
            verify_sdk_image(node, approved)?;
            verify_host_state(&sdk_state_path(node)?)?;
            let channel = io(UnixStream::connect(issuer_socket))?;
            sdk_authority = Some(SdkAuthority::observe(&channel)?);
            sdk_channel = Some(channel);
            let (parent, child) = io(UnixStream::pair())?;
            io(parent.set_read_timeout(Some(Duration::from_secs(5))))?;
            io(parent.set_write_timeout(Some(Duration::from_secs(5))))?;
            readiness = Some(parent);
            let mut issued = Command::new(io(env::current_exe())?);
            issued
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("GITHUB_ACTIONS", "true")
                .env("RUNNER_ENVIRONMENT", "github-hosted")
                .stdin(Stdio::from(OwnedFd::from(child)))
                .arg(if cancel_before_commit {
                    "launch-sdk-cancel"
                } else {
                    "launch-sdk"
                })
                .arg(node)
                .arg(script)
                .arg(client_socket);
            issued
        } else {
            let mut issued = Command::new(io(env::current_exe())?);
            issued
                .arg("allow")
                .arg(client_socket)
                .uid(approved.uid)
                .gid(approved.gid);
            issued
        };
        // Only the non-SDK control uses CommandExt::uid directly. The SDK
        // must create its namespace while still root, before dropping IDs.
        let mut child = io(command.spawn())?;
        // Release the builder's copy of the child-side readiness endpoint.
        drop(command);
        let outcome = (|| {
            let raw =
                unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0u32) };
            if raw < 0 || raw > i64::from(i32::MAX) {
                return Err("E_PEER_PROOF_ISSUER_PIDFD");
            }
            let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
            if let Some((node, _, _)) = sdk {
                let startup = readiness.as_mut().ok_or("E_PEER_SDK_STARTUP_PROTOCOL")?;
                let authority = sdk_authority
                    .as_ref()
                    .ok_or("E_PEER_SDK_AUTHORITY_IDENTITY")?;
                authority.verify()?;
                send_attestation(startup, authority.pid, authority.namespace.as_raw_fd())?;
                let (namespace, mount_namespace) =
                    prepare_sdk_namespace(child.id(), startup, approved)?;
                if !same_namespace(&mount_namespace, &authority.namespace)? {
                    return Err("E_PEER_SDK_AUTHORITY_NAMESPACE_JOIN");
                }
                verify_sdk_process_custody(
                    node,
                    child.id(),
                    &pidfd,
                    &namespace,
                    &mount_namespace,
                    approved,
                )?;
                authority.verify()?;
                eprintln!("T011_LINUX_SDK_SHARED_AUTHORITY_MOUNT_PASS_NONRELEASE");
            }
            let channel = match sdk_channel.take() {
                Some(channel) => channel,
                None => io(UnixStream::connect(issuer_socket))?,
            };
            io(channel.set_write_timeout(Some(Duration::from_secs(3))))?;
            send_attestation(&channel, child.id(), pidfd.as_raw_fd())?;
            if let Some(mut startup) = readiness.take() {
                io(startup.write_all(b"A"))?;
            }
            if !io(child.wait())?.success() {
                return Err("E_PEER_PROOF_ISSUED_CLIENT_FAILED");
            }
            if let Some((node, _, _)) = sdk {
                // No client state or mount may survive in the host view.
                verify_host_state(&sdk_state_path(node)?)?;
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn descriptor_transfer_preserves_identity_but_rejects_host_mount() {
            let (tx, rx) = UnixStream::pair().unwrap();
            let host = File::open("/proc/self/ns/mnt").unwrap();
            send_attestation(&tx, std::process::id(), host.as_raw_fd()).unwrap();
            let (pid, fd) = receive_fixture_descriptor(&rx).unwrap();
            assert_eq!(pid, std::process::id());
            let received = File::from(fd);
            assert!(same_namespace(&host, &received).unwrap());
            assert_eq!(
                verify_private_mount_namespace(&received),
                Err("E_PEER_SDK_MOUNT_NAMESPACE_SHARED")
            );
            let user = File::open("/proc/self/ns/user").unwrap();
            assert_eq!(
                verify_private_mount_namespace(&user),
                Err("E_PEER_SDK_MOUNT_NAMESPACE_TYPE")
            );
        }
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
                if (role == "issue-sdk" || role == "issue-sdk-cancel") && args.next().is_none() =>
            {
                issue(
                    Path::new(&issuer),
                    Path::new(&socket),
                    Some((
                        Path::new(&node),
                        Path::new(&script),
                        role == "issue-sdk-cancel",
                    )),
                )
            }
            (Some(role), Some(node), Some(script), Some(socket), None)
                if role == "launch-sdk" || role == "launch-sdk-cancel" =>
            {
                launch_sdk(
                    Path::new(&node),
                    Path::new(&script),
                    Path::new(&socket),
                    role == "launch-sdk-cancel",
                )
            }
            (Some(role), Some(pid), state, None, None)
                if (role == "inspect-control" && state.is_none())
                    || (role == "inspect-protected" && state.is_some()) =>
            {
                pid.to_str()
                    .and_then(|value| value.parse::<u32>().ok())
                    .ok_or("E_PEER_SDK_INSPECTION_PID")
                    .and_then(|pid| inspect_same_uid(pid, state.as_deref().map(Path::new)))
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
