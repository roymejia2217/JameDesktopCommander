//! Real Windows CREATE_SUSPENDED + creation-time OWNER RIGHTS client pipe
//! acceptance. Disposable same-user test processes, not a trusted MCP host.
#![cfg(windows)]
use jdc_authority_service::{
    windows_creation_custody::OwnerRightsCreationDescriptors,
    windows_pipe_peer::{
        observe_client_sid_after_read, observe_process_sid, verify_live_issued_peer_after_read,
    },
};
use std::{
    ffi::OsStr,
    os::windows::{ffi::OsStrExt, io::BorrowedHandle},
    process::{Command, Stdio},
    ptr,
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_IO_PENDING,
        ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{AdjustTokenPrivileges, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY},
    Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        Threading::{
            CreateEventW, CreateProcessW, GetCurrentProcess, GetExitCodeProcess, OpenProcess,
            OpenProcessToken, OpenThread, ResumeThread, TerminateProcess, WaitForSingleObject,
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_CREATE_THREAD,
            PROCESS_DUP_HANDLE, PROCESS_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
            STARTUPINFOW, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
        },
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}
struct Child {
    process: Handle,
    thread: Handle,
    pid: u32,
    tid: u32,
}
impl Drop for Child {
    fn drop(&mut self) {
        if unsafe { WaitForSingleObject(self.process.0, 0) } != WAIT_OBJECT_0 {
            unsafe {
                TerminateProcess(self.process.0, 1);
                WaitForSingleObject(self.process.0, 5_000);
            }
        }
    }
}
fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}
fn sid_hex() -> String {
    observe_process_sid()
        .expect("kernel token SID")
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}

#[test]
fn fixture_guarded_pipe_client() {
    let Ok(name) = std::env::var("JDC_T011_GUARDED_PIPE_NAME") else {
        return;
    };
    let name = wide(OsStr::new(&name));
    let pipe = Handle(unsafe {
        CreateFileW(
            name.as_ptr(),
            0x0003,
            0,
            ptr::null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    });
    assert_ne!(
        pipe.0, INVALID_HANDLE_VALUE,
        "real protected child connects"
    );
    assert!(!pipe.0.is_null());
    let mut written = 0u32;
    assert_ne!(
        unsafe {
            WriteFile(
                pipe.0,
                b"R".as_ptr().cast(),
                1,
                &mut written,
                ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(written, 1);
    let mut reply = 0u8;
    let mut read = 0u32;
    assert_ne!(
        unsafe {
            ReadFile(
                pipe.0,
                (&mut reply as *mut u8).cast(),
                1,
                &mut read,
                ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(read, 1);
    assert_eq!(reply, b'A');
}

#[test]
fn fixture_guarded_same_sid_intruder() {
    let Ok(pid) = std::env::var("JDC_T011_GUARDED_PID") else {
        return;
    };
    assert_eq!(sid_hex(), std::env::var("JDC_T011_EXPECTED_SID").unwrap());
    let mut token = ptr::null_mut();
    assert_ne!(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        },
        0
    );
    let token = Handle(token);
    assert_ne!(
        unsafe {
            AdjustTokenPrivileges(token.0, 1, ptr::null(), 0, ptr::null_mut(), ptr::null_mut())
        },
        0
    );
    let pid: u32 = pid.parse().expect("real disposable client PID");
    let tid: u32 = std::env::var("JDC_T011_GUARDED_TID")
        .unwrap()
        .parse()
        .unwrap();
    for (rights, is_thread, label) in [
        (PROCESS_DUP_HANDLE, false, "PROCESS_DUP_HANDLE"),
        (PROCESS_VM_READ, false, "PROCESS_VM_READ"),
        (PROCESS_VM_WRITE, false, "PROCESS_VM_WRITE"),
        (PROCESS_CREATE_THREAD, false, "PROCESS_CREATE_THREAD"),
        (0x0004_0000, false, "WRITE_DAC"),
        (THREAD_SET_CONTEXT, true, "THREAD_SET_CONTEXT"),
        (THREAD_SUSPEND_RESUME, true, "THREAD_SUSPEND_RESUME"),
    ] {
        let opened = unsafe {
            if is_thread {
                OpenThread(rights, 0, tid)
            } else {
                OpenProcess(rights, 0, pid)
            }
        };
        let error = unsafe { GetLastError() };
        if !opened.is_null() {
            unsafe {
                CloseHandle(opened);
            }
        }
        assert!(opened.is_null(), "same-SID intruder obtained {label}");
        assert_eq!(
            error, ERROR_ACCESS_DENIED,
            "kernel denial required for {label}"
        );
    }
    if let Ok(name) = std::env::var("JDC_T011_ATTACKER_PIPE") {
        let pipe = Handle(unsafe {
            CreateFileW(
                wide(OsStr::new(&name)).as_ptr(),
                0x0003,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        });
        assert_ne!(
            pipe.0, INVALID_HANDLE_VALUE,
            "same-SID impostor must actually reach a native request channel"
        );
        let mut written = 0u32;
        assert_ne!(
            unsafe {
                WriteFile(
                    pipe.0,
                    b"R".as_ptr().cast(),
                    1,
                    &mut written,
                    ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(written, 1);
        let mut decision = 0u8;
        let mut received = 0u32;
        assert_ne!(
            unsafe {
                ReadFile(
                    pipe.0,
                    (&mut decision as *mut u8).cast(),
                    1,
                    &mut received,
                    ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(received, 1);
        assert_eq!(decision, b'D', "unissued same-SID read must be DENIED");
        let mut extra = 0u8;
        let status = unsafe {
            ReadFile(
                pipe.0,
                (&mut extra as *mut u8).cast(),
                1,
                &mut received,
                ptr::null_mut(),
            )
        };
        let error = unsafe { GetLastError() };
        assert_eq!(status, 0, "denied peer must receive no protected bytes");
        assert!(
            error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED,
            "denied pipe must be closed by the native authority"
        );
    }
}

fn create_guarded_process(
    name: &str,
    protected: bool,
    executable: &OsStr,
    command_line: &str,
    diagnostic: Option<&std::path::Path>,
) -> Child {
    let app = wide(executable);
    let mut command = wide(OsStr::new(command_line));
    let mut token = ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0
    );
    let token = Handle(token);
    let descriptors = if protected {
        Some(
            OwnerRightsCreationDescriptors::from_primary_token(unsafe {
                BorrowedHandle::borrow_raw(token.0)
            })
            .expect("actual primary token owner ACLs"),
        )
    } else {
        None
    };
    // Borrowed creation attributes must not outlive their owned descriptors.
    let borrowed = descriptors.as_ref().map(|x| x.borrow_attributes());
    // Isolated test-only Unicode environment. Does not mutate the host's env.
    let root = std::env::var("SystemRoot").expect("Windows environment");
    let diagnostic_entry = diagnostic
        .map(|path| format!("JDC_T011_SDK_DIAGNOSTIC={}\0", path.display()))
        .unwrap_or_default();
    let env = format!("JDC_T011_GUARDED_PIPE_NAME={name}\0{diagnostic_entry}SystemRoot={root}\0\0");
    let mut env: Vec<u16> = env.encode_utf16().collect();
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    assert_ne!(
        unsafe {
            CreateProcessW(
                app.as_ptr(),
                command.as_mut_ptr(),
                borrowed.as_ref().map_or(ptr::null(), |a| a.process()),
                borrowed
                    .as_ref()
                    .map_or(ptr::null(), |a| a.primary_thread()),
                0,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                env.as_mut_ptr().cast(),
                ptr::null(),
                &startup,
                &mut info,
            )
        },
        0,
        "kernel must create a suspended disposable process"
    );
    assert!(!info.hProcess.is_null() && !info.hThread.is_null());
    Child {
        process: Handle(info.hProcess),
        thread: Handle(info.hThread),
        pid: info.dwProcessId,
        tid: info.dwThreadId,
    }
}

fn create_guarded_child(name: &str, protected: bool) -> Child {
    let exe = std::env::current_exe().expect("test-owned executable");
    let command = format!(
        "\"{}\" --exact fixture_guarded_pipe_client --nocapture",
        exe.display()
    );
    create_guarded_process(name, protected, exe.as_os_str(), &command, None)
}

fn overlapped_byte(pipe: HANDLE, byte: &mut u8, read: bool) {
    let event = Handle(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) });
    assert!(!event.0.is_null());
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = event.0;
    let ok = unsafe {
        if read {
            ReadFile(pipe, (byte as *mut u8).cast(), 1, ptr::null_mut(), &mut ov)
        } else {
            WriteFile(pipe, (byte as *mut u8).cast(), 1, ptr::null_mut(), &mut ov)
        }
    };
    if ok == 0 {
        assert_eq!(unsafe { GetLastError() }, ERROR_IO_PENDING);
        if unsafe { WaitForSingleObject(event.0, 7_000) } != WAIT_OBJECT_0 {
            unsafe { CancelIoEx(pipe, &ov) };
            let mut drained = 0u32;
            unsafe { GetOverlappedResult(pipe, &ov, &mut drained, 1) };
            panic!("bounded pipe response timed out");
        }
    }
    let mut count = 0u32;
    let result = unsafe { GetOverlappedResult(pipe, &ov, &mut count, 0) };
    let error = if result == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    assert_ne!(
        result, 0,
        "overlapped pipe operation failed (read={read}, win32={error})"
    );
    assert_eq!(count, 1);
}

#[test]
fn protected_launched_client_can_write_but_same_sid_cannot_duplicate_its_pipe() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!(r"\\.\pipe\JDC-T011-GUARDED-{}-{unique}", std::process::id());
    let server = Handle(unsafe {
        CreateNamedPipeW(
            wide(OsStr::new(&name)).as_ptr(),
            0x0003 | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            128,
            128,
            0,
            ptr::null(),
        )
    });
    assert_ne!(server.0, INVALID_HANDLE_VALUE);
    let event = Handle(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) });
    assert!(!event.0.is_null());
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = event.0;
    let connected = unsafe { ConnectNamedPipe(server.0, &mut ov) };
    let error = if connected == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    assert!(connected != 0 || error == ERROR_IO_PENDING || error == ERROR_PIPE_CONNECTED);

    // RED must fail with the default process/thread ACL, then become GREEN
    // when the kernel receives the protected descriptors at creation.
    let child = create_guarded_child(&name, true);
    assert_eq!(
        unsafe { WaitForSingleObject(child.process.0, 0) },
        WAIT_TIMEOUT
    );
    assert_eq!(unsafe { ResumeThread(child.thread.0) }, 1);
    if error == ERROR_IO_PENDING {
        if unsafe { WaitForSingleObject(event.0, 7_000) } != WAIT_OBJECT_0 {
            unsafe { CancelIoEx(server.0, &ov) };
            let mut drained = 0u32;
            unsafe { GetOverlappedResult(server.0, &ov, &mut drained, 1) };
            panic!("named-pipe client failed to connect");
        }
        let mut count = 0u32;
        assert_ne!(
            unsafe { GetOverlappedResult(server.0, &ov, &mut count, 0) },
            0
        );
    }
    let mut request = 0u8;
    overlapped_byte(server.0, &mut request, true);
    assert_eq!(
        request, b'R',
        "legitimate test child must send exact payload"
    );
    assert_eq!(
        unsafe { WaitForSingleObject(child.process.0, 0) },
        WAIT_TIMEOUT
    );
    assert_eq!(
        verify_live_issued_peer_after_read(
            unsafe { BorrowedHandle::borrow_raw(server.0) },
            unsafe { BorrowedHandle::borrow_raw(child.process.0) }
        ),
        Ok(()),
        "original live client is the pipe connector (not per-message writer proof)"
    );
    assert_eq!(
        observe_client_sid_after_read(unsafe { BorrowedHandle::borrow_raw(server.0) }),
        Ok(observe_process_sid().unwrap())
    );

    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "fixture_guarded_same_sid_intruder",
            "--nocapture",
        ])
        .env("JDC_T011_GUARDED_PID", child.pid.to_string())
        .env("JDC_T011_GUARDED_TID", child.tid.to_string())
        .env("JDC_T011_EXPECTED_SID", sid_hex())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("independent real Windows intruder");
    let mut reply = b'A';
    overlapped_byte(server.0, &mut reply, false);
    assert!(
        status.status.success(),
        "same-SID custody proof failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert_eq!(
        unsafe { WaitForSingleObject(child.process.0, 7_000) },
        WAIT_OBJECT_0
    );
    let mut code = u32::MAX;
    assert_ne!(unsafe { GetExitCodeProcess(child.process.0, &mut code) }, 0);
    assert_eq!(code, 0);
}

struct OwnedSentinel(std::path::PathBuf);
impl Drop for OwnedSentinel {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
struct PeerCleanup(std::process::Child);
impl Drop for PeerCleanup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct OwnedDiagnostic(std::path::PathBuf);
impl Drop for OwnedDiagnostic {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Ok(message) = std::fs::read_to_string(&self.0) {
                eprintln!("T011_SDK_CHILD_FAILURE_DIAGNOSTIC: {message}");
            }
        }
        let _ = std::fs::remove_file(&self.0);
    }
}

/// An actual Node MCP SDK Client.callTool is issued inside the protected
/// CREATE_SUSPENDED child, then its native pipe origin is authenticated.
/// CI-only: this is neither an installed privileged issuer nor a shipping
/// JDC handler. The parent retains the file HANDLE before client admission.
#[test]
#[ignore = "Requires official SDK node_modules and JDC_T011_NODE_BINARY; CI exercises explicitly"]
fn protected_issued_sdk_read_preserves_exact_bytes_and_rejects_same_sid() {
    use std::io::Read;
    use std::path::PathBuf;
    let node = PathBuf::from(
        std::env::var_os("JDC_T011_NODE_BINARY")
            .expect("test-only pinned Node executable path required"),
    );
    assert!(
        node.is_absolute() && node.is_file(),
        "actual Node executable required"
    );
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/security/support/t011-windows-issued-sdk-client.mjs");
    assert!(script.is_file(), "real official-SDK test client source");
    const BYTES: &[u8] = &[0x00, 0xff, 0x81, 0x2a, 0x4a, 0x44, 0x43, 0x0a];
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sentinel = std::env::temp_dir().join(format!(
        "jdc-t011-sdk-sentinel-{}-{unique}.bin",
        std::process::id()
    ));
    std::fs::write(&sentinel, BYTES).expect("test-owned sentinel creation");
    let _owned_sentinel = OwnedSentinel(sentinel.clone());
    let mut retained_file = std::fs::File::open(&sentinel)
        .expect("issuer retains original file object before SDK admission");

    let name = format!(r"\\.\pipe\JDC-T011-SDK-{}-{unique}", std::process::id());
    let server = Handle(unsafe {
        CreateNamedPipeW(
            wide(OsStr::new(&name)).as_ptr(),
            0x0003 | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            2,
            128,
            128,
            0,
            ptr::null(),
        )
    });
    assert_ne!(server.0, INVALID_HANDLE_VALUE);
    let event = Handle(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) });
    assert!(!event.0.is_null());
    let mut pending: OVERLAPPED = unsafe { std::mem::zeroed() };
    pending.hEvent = event.0;
    let connected = unsafe { ConnectNamedPipe(server.0, &mut pending) };
    let connect_error = if connected == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    assert!(
        connected != 0
            || connect_error == ERROR_IO_PENDING
            || connect_error == ERROR_PIPE_CONNECTED
    );

    let diagnostic = std::env::temp_dir().join(format!(
        "jdc-t011-sdk-child-{}-{unique}.log",
        std::process::id()
    ));
    let _owned_diagnostic = OwnedDiagnostic(diagnostic.clone());
    let cmd = format!(
        r#""{}" "{}" "{}" "{}""#,
        node.display(),
        script.display(),
        name,
        diagnostic.display()
    );
    // RED with default ACL: a same-SID process obtained PROCESS_DUP_HANDLE.
    // GREEN requires creation-time OWNER RIGHTS on this actual Node SDK child.
    let child = create_guarded_process(&name, true, node.as_os_str(), &cmd, Some(&diagnostic));
    assert_eq!(unsafe { ResumeThread(child.thread.0) }, 1);
    if connect_error == ERROR_IO_PENDING {
        if unsafe { WaitForSingleObject(event.0, 7_000) } != WAIT_OBJECT_0 {
            unsafe { CancelIoEx(server.0, &pending) };
            let mut exit_code = u32::MAX;
            assert_ne!(
                unsafe { GetExitCodeProcess(child.process.0, &mut exit_code) },
                0
            );
            let diagnostic_text = std::fs::read_to_string(&diagnostic).unwrap_or_default();
            panic!("issued SDK never reached native pipe; exit {exit_code}; {diagnostic_text}");
        }
        let mut count = 0u32;
        assert_ne!(
            unsafe { GetOverlappedResult(server.0, &pending, &mut count, 0) },
            0
        );
    }
    // The official-SDK native adapter waits for admission challenge 'C'
    // before sending the single request byte 'R'. No file bytes precede it.
    let mut challenge = b'C';
    overlapped_byte(server.0, &mut challenge, false);
    let mut request = 0u8;
    overlapped_byte(server.0, &mut request, true);
    assert_eq!(
        request, b'R',
        "real SDK tool must request the protected read"
    );
    assert_eq!(
        verify_live_issued_peer_after_read(
            unsafe { BorrowedHandle::borrow_raw(server.0) },
            unsafe { BorrowedHandle::borrow_raw(child.process.0) }
        ),
        Ok(()),
        "retained issuer process HANDLE must match actual kernel pipe origin"
    );
    assert_eq!(
        observe_client_sid_after_read(unsafe { BorrowedHandle::borrow_raw(server.0) }),
        Ok(observe_process_sid().unwrap()),
        "SDK child token must be observed, not claimed in request parameters"
    );

    // A second real pipe instance admits the attacker far enough to issue R.
    // It must receive D only after the kernel identifies its distinct PID.
    let denied_pipe = Handle(unsafe {
        CreateNamedPipeW(
            wide(OsStr::new(&name)).as_ptr(),
            0x0003 | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            2,
            128,
            128,
            0,
            ptr::null(),
        )
    });
    assert_ne!(
        denied_pipe.0, INVALID_HANDLE_VALUE,
        "native broker must expose one test-only adversarial connection"
    );
    let denied_event = Handle(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) });
    assert!(!denied_event.0.is_null());
    let mut denied_pending: OVERLAPPED = unsafe { std::mem::zeroed() };
    denied_pending.hEvent = denied_event.0;
    let connected = unsafe { ConnectNamedPipe(denied_pipe.0, &mut denied_pending) };
    let connect_error = if connected == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    assert!(
        connected != 0
            || connect_error == ERROR_IO_PENDING
            || connect_error == ERROR_PIPE_CONNECTED
    );
    let mut attacker = PeerCleanup(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fixture_guarded_same_sid_intruder",
                "--nocapture",
            ])
            .env("JDC_T011_GUARDED_PID", child.pid.to_string())
            .env("JDC_T011_GUARDED_TID", child.tid.to_string())
            .env("JDC_T011_EXPECTED_SID", sid_hex())
            .env("JDC_T011_ATTACKER_PIPE", &name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("independent real Windows same-SID read adversary"),
    );
    assert_ne!(attacker.0.id(), child.pid);
    if connect_error == ERROR_IO_PENDING {
        assert_eq!(
            unsafe { WaitForSingleObject(denied_event.0, 7_000) },
            WAIT_OBJECT_0,
            "unissued client must actually connect to native IPC"
        );
        let mut count = 0u32;
        assert_ne!(
            unsafe { GetOverlappedResult(denied_pipe.0, &denied_pending, &mut count, 0) },
            0
        );
    }
    let mut hostile_request = 0u8;
    overlapped_byte(denied_pipe.0, &mut hostile_request, true);
    assert_eq!(hostile_request, b'R');
    assert_eq!(
        observe_client_sid_after_read(unsafe { BorrowedHandle::borrow_raw(denied_pipe.0) }),
        Ok(observe_process_sid().unwrap()),
        "the rejected process has the same real Windows SID"
    );
    assert!(
        verify_live_issued_peer_after_read(
            unsafe { BorrowedHandle::borrow_raw(denied_pipe.0) },
            unsafe { BorrowedHandle::borrow_raw(child.process.0) }
        )
        .is_err(),
        "unissued same-SID PID must not receive file authority"
    );
    let mut denied = b'D';
    overlapped_byte(denied_pipe.0, &mut denied, false);
    drop(denied_pipe);
    assert!(
        attacker
            .0
            .wait()
            .expect("unissued adversary process must exit")
            .success(),
        "same-SID intruder obtained custody or any protected response bytes"
    );

    let mut content = Vec::new();
    retained_file
        .read_to_end(&mut content)
        .expect("read original retained file HANDLE");
    assert_eq!(
        content, BYTES,
        "preopened test file must supply the exact bytes"
    );
    let mut response = Vec::with_capacity(5 + content.len());
    response.push(b'A');
    response.extend_from_slice(&(content.len() as u32).to_be_bytes());
    response.extend_from_slice(&content);
    for mut byte in response {
        overlapped_byte(server.0, &mut byte, false);
    }
    // The SDK frame reader deliberately requires EOF before returning bytes.
    // The retained native pipe handle must be closed after the full response.
    drop(server);
    assert_eq!(
        unsafe { WaitForSingleObject(child.process.0, 8_000) },
        WAIT_OBJECT_0,
        "official SDK client must finish the complete native-byte call"
    );
    let mut exit_code = u32::MAX;
    assert_ne!(
        unsafe { GetExitCodeProcess(child.process.0, &mut exit_code) },
        0
    );
    assert_eq!(exit_code, 0, "official SDK must verify every returned byte");
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        BYTES,
        "test-owned native sentinel bytes must remain unchanged"
    );
}
