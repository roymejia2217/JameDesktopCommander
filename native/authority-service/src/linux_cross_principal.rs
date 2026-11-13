//! CI-only proof of Linux kernel Unix-socket credentials across OS principals.
//! Deliberately non-shipping: no listener, identity grant, policy store,
//! privileged file operation, or IPC authentication is wired into JDC.
#![cfg(test)]

use crate::{
    linux_peer::observe_kernel_peer,
    peer_policy::{verify_distinct_peer, DedicatedAccount},
    IdentityDenied,
};
use std::{
    env, fs,
    io::{Read, Write},
    os::{unix::fs::PermissionsExt, unix::net::UnixListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct OwnedFixtureDir(PathBuf);
impl Drop for OwnedFixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct OwnedProcess(Child);
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn numeric_principal_id(kind: &str) -> u32 {
    let output = Command::new("/usr/bin/id")
        .args([kind, "nobody"])
        .output()
        .expect("standard Linux id executable");
    assert!(output.status.success(), "nobody principal is required");
    let text = std::str::from_utf8(&output.stdout).expect("numeric principal is ASCII");
    text.trim().parse::<u32>().expect("numeric Linux principal")
}

#[test]
#[ignore = "test-owned Unix socket with two real OS principals on an ephemeral GitHub Linux runner"]
fn distinct_os_user_socket_credentials_match_kernel_not_payload() {
    assert_eq!(env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(env::var("RUNNER_OS").as_deref(), Ok("Linux"));
    assert_eq!(
        env::var("RUNNER_ENVIRONMENT").as_deref(),
        Ok("github-hosted")
    );
    assert_eq!(
        env::var("GITHUB_REPOSITORY").as_deref(),
        Ok("roymejia2217/JameDesktopCommander")
    );

    let service_uid = unsafe { libc::geteuid() };
    let service_gid = unsafe { libc::getegid() };
    let service_pid = unsafe { libc::getpid() };
    let client = DedicatedAccount {
        uid: numeric_principal_id("-u"),
        gid: numeric_principal_id("-g"),
    };
    assert_ne!(service_uid, 0, "runner must not be privileged");
    assert_ne!(service_gid, 0, "runner must have a nonroot primary group");
    assert_ne!(service_uid, client.uid, "fixture must use separate UID");
    assert_ne!(service_gid, client.gid, "fixture must use separate GID");
    assert_ne!(client.uid, 0);
    assert_ne!(client.gid, 0);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch");
    let fixture_dir = env::temp_dir().join(format!(
        "jdc-t011-peer-{}-{}",
        std::process::id(),
        timestamp.as_nanos()
    ));
    fs::create_dir(&fixture_dir).expect("create unique test-owned directory");
    let _cleanup = OwnedFixtureDir(fixture_dir.clone());
    // Other test principal can traverse, but cannot enumerate or write here.
    fs::set_permissions(&fixture_dir, fs::Permissions::from_mode(0o711))
        .expect("restrict test-owned directory");

    // CI checkout and Rust target directories can be private to runner UID.
    // Place an immutable-for-client copy in our owned executable fixture.
    let executable = env::current_exe().expect("current test harness path");
    let client_executable = fixture_dir.join("peer-client-test");
    fs::copy(&executable, &client_executable).expect("copy owned test-only binary");
    fs::set_permissions(&client_executable, fs::Permissions::from_mode(0o755))
        .expect("make owned test binary executable for foreign UID");
    let reachable = Command::new("/usr/bin/sudo")
        .args(["-n", "-u", "nobody", "--", "/usr/bin/test", "-x"])
        .arg(&client_executable)
        .status()
        .expect("test executable preflight for distinct UID");
    assert!(
        reachable.success(),
        "foreign principal cannot execute owned test binary"
    );

    let path = fixture_dir.join("peer.sock");
    let listener = UnixListener::bind(&path).expect("bind unique test-only socket");
    // A randomized, no-operation test socket must accept a different UID.
    // This is NOT a production service endpoint or an authorization policy.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o722))
        .expect("permit test-only cross-UID connection");
    listener.set_nonblocking(true).expect("bounded accept");

    let path_arg = format!("JDC_PEER_FOREIGN_SOCKET={}", path.display());
    let child = Command::new("/usr/bin/sudo")
        .args(["-n", "-u", "nobody", "--", "/usr/bin/env"])
        .arg(&path_arg)
        .arg(&client_executable)
        .args([
            "--ignored",
            "--exact",
            "linux_cross_principal::foreign_client_subprocess_fixture",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("launch dedicated nobody Unix-socket client");
    let mut _child = OwnedProcess(child);

    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut accepted, _) = loop {
        match listener.accept() {
            Ok(socket) => break socket,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                match _child.0.try_wait() {
                    Ok(Some(exit)) => panic!(
                        "foreign client exited without connecting (exit code {:?})",
                        exit.code()
                    ),
                    Ok(None) => thread::sleep(Duration::from_millis(25)),
                    Err(_) => panic!("failed to observe foreign client process"),
                }
            }
            Err(e) => panic!("bounded cross-principal accept failed: {e}"),
        }
    };
    accepted
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded test socket read");
    let observed = observe_kernel_peer(&accepted).expect("Linux SO_PEERCRED must be available");
    let mut raw_pid = [0u8; 4];
    accepted
        .read_exact(&mut raw_pid)
        .expect("foreign client test marker");
    let child_claimed_pid = u32::from_ne_bytes(raw_pid);

    assert_ne!(observed.pid, service_pid);
    assert_eq!(observed.pid as u32, child_claimed_pid);
    assert_eq!(observed.uid, client.uid);
    assert_eq!(observed.gid, client.gid);
    assert_eq!(
        verify_distinct_peer(observed, client, service_uid, service_gid, service_pid),
        Ok(())
    );
    assert_eq!(
        verify_distinct_peer(
            observed,
            DedicatedAccount {
                uid: service_uid,
                gid: service_gid
            },
            service_uid,
            service_gid,
            service_pid
        ),
        Err(IdentityDenied)
    );
    assert_eq!(
        verify_distinct_peer(observed, client, service_uid, observed.gid, service_pid),
        Err(IdentityDenied)
    );
    assert!(_child.0.wait().expect("foreign client completes").success());
    drop(accepted);
    drop(listener);
    fs::remove_dir_all(&fixture_dir).expect("remove test-only socket and executable");
    assert!(!fixture_dir.exists(), "owned test fixture must be absent");
    println!("LINUX_DISTINCT_USER_SOCKET_KERNEL_TEST=PASS");
}

#[test]
#[ignore = "only invoked as a bounded subprocess of the ephemeral cross-principal test"]
fn foreign_client_subprocess_fixture() {
    let path = env::var_os("JDC_PEER_FOREIGN_SOCKET").expect("test-owned socket required");
    let mut stream = std::os::unix::net::UnixStream::connect(path)
        .expect("connect from actual separate Linux principal");
    stream
        .write_all(&std::process::id().to_ne_bytes())
        .expect("write process identity witness");
}
