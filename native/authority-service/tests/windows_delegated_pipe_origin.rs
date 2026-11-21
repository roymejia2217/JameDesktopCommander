//! Non-shipping Windows pipe-handle delegation falsification.
//! An issuer-pinned connecting PID is not per-request writer identity.
//! Uses only a named pipe and processes owned by this integration test.
#![cfg(windows)]
use jdc_authority_service::windows_pipe_peer::{
    observe_client_sid_after_read, observe_process_sid, verify_live_issued_peer_after_read,
};
use std::{
    os::windows::io::BorrowedHandle,
    process::{Child, Command, Stdio},
    ptr,
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_IO_PENDING,
        ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    },
    Security::{AdjustTokenPrivileges, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY},
    Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        Threading::{
            CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForSingleObject,
            PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
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
struct ChildCleanup(Child);
impl Drop for ChildCleanup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
fn process_sid_hex() -> String {
    observe_process_sid()
        .expect("real process-token SID")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn finish_io(pipe: HANDLE, event: HANDLE, ov: &OVERLAPPED) -> u32 {
    if unsafe { WaitForSingleObject(event, 7_000) } != WAIT_OBJECT_0 {
        unsafe { CancelIoEx(pipe, ov) };
        let mut drained = 0u32;
        unsafe { GetOverlappedResult(pipe, ov, &mut drained, 1) };
        panic!("real named-pipe event did not complete within bound");
    }
    let mut count = 0u32;
    assert_ne!(
        unsafe { GetOverlappedResult(pipe, ov, &mut count, 0) },
        0,
        "real kernel overlapped I/O completion"
    );
    count
}

#[test]
fn fixture_same_sid_attacker_writes_via_duplicated_client_handle() {
    let Ok(source_pid) = std::env::var("JDC_T011_PIPE_SOURCE_PID") else {
        return;
    };
    assert_eq!(
        process_sid_hex(),
        std::env::var("JDC_T011_EXPECTED_SID").unwrap()
    );
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
        0,
        "test intruder must disable its enabled privileges"
    );
    let source_pid: u32 = source_pid.parse().expect("test-owned connecting PID");
    assert_ne!(source_pid, std::process::id());
    let client_handle: usize = std::env::var("JDC_T011_PIPE_CLIENT_HANDLE")
        .expect("test-only handle number")
        .parse()
        .expect("numeric test handle");
    let source = Handle(unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, source_pid) });
    assert!(
        !source.0.is_null(),
        "real same-user default process permits duplication"
    );
    let mut copied = ptr::null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                source.0,
                client_handle as HANDLE,
                GetCurrentProcess(),
                &mut copied,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        },
        0,
        "real kernel must transfer test-owned pipe client handle"
    );
    let delegated = Handle(copied);
    let byte = b'X';
    let mut written = 0u32;
    assert_ne!(
        unsafe { WriteFile(delegated.0, &byte, 1, &mut written, ptr::null_mut()) },
        0,
        "independent same-SID writer must send the actual pipe request"
    );
    assert_eq!(written, 1);
}

#[test]
fn delegated_writer_retains_original_connector_pid_without_proving_writer_origin() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock for disposable pipe name")
        .as_nanos();
    let name = format!(
        r"\\.\pipe\JDC-T011-DELEGATED-{}-{unique}",
        std::process::id()
    );
    let encoded = wide(&name);
    let raw_server = unsafe {
        CreateNamedPipeW(
            encoded.as_ptr(),
            0x0003 | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            128,
            128,
            0,
            ptr::null(),
        )
    };
    assert_ne!(raw_server, INVALID_HANDLE_VALUE, "real named pipe creation");
    assert!(!raw_server.is_null());
    let server = Handle(raw_server);
    let event = Handle(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) });
    assert!(!event.0.is_null());
    let mut connection: OVERLAPPED = unsafe { std::mem::zeroed() };
    connection.hEvent = event.0;
    let connected = unsafe { ConnectNamedPipe(server.0, &mut connection) };
    let error = if connected == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    assert!(
        connected != 0 || error == ERROR_IO_PENDING || error == ERROR_PIPE_CONNECTED,
        "real kernel connection setup: {error}"
    );
    // This parent is the original named-pipe connector. It intentionally
    // NEVER writes a request byte: the independent intruder does.
    let raw_client = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            0x0003,
            0,
            ptr::null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    assert_ne!(raw_client, INVALID_HANDLE_VALUE, "test client connects");
    assert!(!raw_client.is_null());
    let original_client = Handle(raw_client);
    if error == ERROR_IO_PENDING {
        let _ = finish_io(server.0, event.0, &connection);
    }
    let mut connected_pid = 0u32;
    assert_ne!(
        unsafe { GetNamedPipeClientProcessId(server.0, &mut connected_pid) },
        0
    );
    assert_eq!(connected_pid, std::process::id());

    let mut attacker = ChildCleanup(
        Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "fixture_same_sid_attacker_writes_via_duplicated_client_handle",
                "--nocapture",
            ])
            .env("JDC_T011_PIPE_SOURCE_PID", connected_pid.to_string())
            .env(
                "JDC_T011_PIPE_CLIENT_HANDLE",
                (original_client.0 as usize).to_string(),
            )
            .env("JDC_T011_EXPECTED_SID", process_sid_hex())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("independent same-user actual attacker"),
    );
    assert_ne!(attacker.0.id(), std::process::id());
    let read_event = Handle(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) });
    assert!(!read_event.0.is_null());
    let mut read_ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    read_ov.hEvent = read_event.0;
    let mut observed = 0u8;
    let read = unsafe {
        ReadFile(
            server.0,
            (&mut observed as *mut u8).cast(),
            1,
            ptr::null_mut(),
            &mut read_ov,
        )
    };
    let size = if read != 0 {
        let mut len = 0u32;
        assert_ne!(
            unsafe { GetOverlappedResult(server.0, &read_ov, &mut len, 0) },
            0
        );
        len
    } else {
        assert_eq!(unsafe { GetLastError() }, ERROR_IO_PENDING);
        finish_io(server.0, read_event.0, &read_ov)
    };
    assert_eq!(size, 1);
    assert_eq!(observed, b'X', "only the real delegated writer sends X");
    assert!(
        attacker
            .0
            .wait()
            .expect("attacker finished actual write")
            .success(),
        "independent attacker must successfully duplicate and write"
    );
    assert_eq!(
        observe_client_sid_after_read(unsafe { BorrowedHandle::borrow_raw(server.0) }),
        Ok(observe_process_sid().expect("same-SID test token")),
        "a same-SID delegated writer remains indistinguishable by SID"
    );
    let original_process = Handle(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | 0x0010_0000,
            0,
            connected_pid,
        )
    });
    assert!(!original_process.0.is_null());
    // This test preserves the *falsified* authorization hypothesis:
    // the connecting PID is still the original process even though the
    // request byte was written only by the independent same-SID intruder.
    // Therefore a successful match is OBSERVATIONAL and MUST NEVER grant
    // file access, even when the original process handle remains live.
    assert_eq!(
        verify_live_issued_peer_after_read(
            unsafe { BorrowedHandle::borrow_raw(server.0) },
            unsafe { BorrowedHandle::borrow_raw(original_process.0) },
        ),
        Ok(()),
        "a connector PID match does not prove actual message writer origin"
    );
}
