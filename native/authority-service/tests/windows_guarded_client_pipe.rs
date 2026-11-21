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
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED,
        HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
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
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_DUP_HANDLE,
            PROCESS_INFORMATION, STARTUPINFOW, THREAD_SET_CONTEXT,
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
        (0x0004_0000, false, "WRITE_DAC"),
        (THREAD_SET_CONTEXT, true, "THREAD_SET_CONTEXT"),
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
}

fn create_guarded_child(name: &str, protected: bool) -> Child {
    let exe = std::env::current_exe().expect("test-owned executable");
    let app = wide(exe.as_os_str());
    let cmd = format!(
        "\"{}\" --exact fixture_guarded_pipe_client --nocapture",
        exe.display()
    );
    let mut command = wide(OsStr::new(&cmd));
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
    let proc_attrs = descriptors.as_ref().map(|x| x.process_attributes());
    let thread_attrs = descriptors.as_ref().map(|x| x.primary_thread_attributes());
    // Isolated test-only Unicode environment. Does not mutate the host's env.
    let root = std::env::var("SystemRoot").expect("Windows environment");
    let env = format!("JDC_T011_GUARDED_PIPE_NAME={name}\0SystemRoot={root}\0\0");
    let mut env: Vec<u16> = env.encode_utf16().collect();
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    assert_ne!(
        unsafe {
            CreateProcessW(
                app.as_ptr(),
                command.as_mut_ptr(),
                proc_attrs.as_ref().map_or(ptr::null(), |a| a),
                thread_attrs.as_ref().map_or(ptr::null(), |a| a),
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
    assert_ne!(unsafe { GetOverlappedResult(pipe, &ov, &mut count, 0) }, 0);
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
