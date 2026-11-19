//! T011 non-shipping, GitHub-runner-only kernel/IPC/read integration proof.
//! NOT a trusted policy source, IPC protocol, installation or MCP authority.
//! The administrator-owned fixture supplies the root and socket by CLI;
//! those parameters are NOT valid means to grant production privileges.
#[cfg(target_os = "linux")]
mod proof {
    use jdc_authority_service::{
        confined_read::read_regular_at,
        linux_peer::observe_kernel_peer,
        peer_policy::{verify_distinct_peer, DedicatedAccount},
        verify_service_identity,
    };
    use std::{
        env,
        fs::{self, File},
        io::{Read, Write},
        mem::MaybeUninit,
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
        path::Path,
        process::ExitCode,
        ptr, thread,
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

    fn serve(root: &Path, socket: &Path) -> Result<(), &'static str> {
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
        io(listener.set_nonblocking(true))?;
        let deadline = Instant::now() + Duration::from_secs(12);
        let mut denied = false;
        // The second eligible request is intentionally launched from another
        // process under the SAME client UID/GID: pure peer identity cannot
        // prove which process originated a legitimate MCP host request.
        let mut accepted_peer_pid: Option<i32> = None;
        let mut admitted_count = 0usize;
        while !denied || admitted_count < 2 {
            let (mut conn, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Err(_) => return Err("E_PEER_PROOF_ACCEPT_TIMEOUT"),
            };
            io(conn.set_read_timeout(Some(Duration::from_secs(3))))?;
            io(conn.set_write_timeout(Some(Duration::from_secs(3))))?;
            let peer = observe_kernel_peer(&conn).map_err(|_| "E_PEER_PROOF_KERNEL_CREDENTIALS")?;
            let valid =
                verify_distinct_peer(peer, approved_client, service_uid, service_gid, service_pid)
                    .is_ok();
            if !valid {
                if denied {
                    return Err("E_PEER_PROOF_REPEATED_FOREIGN_CLIENT");
                }
                io(conn.write_all(b"D"))?;
                denied = true;
                continue;
            }
            if admitted_count >= 2 {
                return Err("E_PEER_PROOF_EXCESS_CLIENTS");
            }
            if let Some(first_pid) = accepted_peer_pid {
                if peer.pid == first_pid {
                    return Err("E_PEER_PROOF_SAME_PROCESS_REUSED");
                }
                // Both independent PIDs have passed the same UID/GID-only
                // peer policy. This is the precise *origin* counterexample,
                // not proof of a protected client process or a safe broker.
                if peer.uid != approved_client.uid || peer.gid != approved_client.gid {
                    return Err("E_PEER_PROOF_UNEXPECTED_SECOND_CREDENTIALS");
                }
            } else {
                accepted_peer_pid = Some(peer.pid);
            }
            let mut request = [0_u8; 1];
            io(conn.read_exact(&mut request))?;
            if request != *b"R" {
                return Err("E_PEER_PROOF_INVALID_REQUEST");
            }
            // The client supplies NO pathname, root, epoch, PID, UID or authority.
            // The test fixture selects the sole fixed filename.
            let bytes = read_regular_at(&root_fd, Path::new("service.bin"))
                .map_err(|_| "E_PEER_PROOF_NATIVE_READ_DENIED")?;
            if bytes != AUTHORIZED_CONTENT {
                return Err("E_PEER_PROOF_UNEXPECTED_OBJECT_BYTES");
            }
            let length =
                u32::try_from(bytes.len()).map_err(|_| "E_PEER_PROOF_RESPONSE_TOO_LARGE")?;
            io(conn.write_all(b"A"))?;
            io(conn.write_all(&length.to_be_bytes()))?;
            io(conn.write_all(&bytes))?;
            admitted_count += 1;
            if admitted_count == 2 {
                eprintln!("T011_LINUX_SAME_UID_UNATTESTED_SECOND_PROCESS_READ_NONRELEASE");
            }
        }
        eprintln!("T011_LINUX_OS_PEER_BOUND_NATIVE_READ_PASS_NONRELEASE");
        Ok(())
    }

    fn request(
        socket: &Path,
        should_allow: bool,
        untrusted_same_uid_origin: bool,
    ) -> Result<(), &'static str> {
        if untrusted_same_uid_origin && !should_allow {
            return Err("E_PEER_PROOF_INVALID_UNTRUSTED_CASE");
        }
        let mut conn = io(UnixStream::connect(socket))?;
        io(conn.set_read_timeout(Some(Duration::from_secs(3))))?;
        io(conn.set_write_timeout(Some(Duration::from_secs(3))))?;
        if should_allow {
            io(conn.write_all(b"R"))?;
        }
        let mut decision = [0_u8; 1];
        io(conn.read_exact(&mut decision))?;
        if !should_allow {
            if decision != *b"D" {
                return Err("E_PEER_PROOF_FOREIGN_CLIENT_ACCEPTED");
            }
            let mut extra = [0_u8; 1];
            if io(conn.read(&mut extra))? != 0 {
                return Err("E_PEER_PROOF_DENIED_BYTES_LEAKED");
            }
            eprintln!("T011_LINUX_FOREIGN_PEER_DENIED_NO_BYTES");
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
        if untrusted_same_uid_origin {
            // A second independent process deliberately invoked the same
            // admitted request without an independently attested host origin.
            eprintln!("T011_LINUX_SAME_UID_UNTRUSTED_CLIENT_READ_NONRELEASE");
        } else {
            eprintln!("T011_LINUX_LEGITIMATE_CLIENT_RECEIVED_BOUND_BYTES");
        }
        Ok(())
    }

    pub fn main() -> ExitCode {
        let mut args = env::args_os().skip(1);
        let result = match (args.next(), args.next(), args.next(), args.next()) {
            (Some(role), Some(root), Some(socket), None) if role == "serve" => {
                serve(Path::new(&root), Path::new(&socket))
            }
            (Some(role), Some(socket), None, None) if role == "allow" => {
                request(Path::new(&socket), true, false)
            }
            (Some(role), Some(socket), None, None) if role == "impersonate" => {
                request(Path::new(&socket), true, true)
            }
            (Some(role), Some(socket), None, None) if role == "deny" => {
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
