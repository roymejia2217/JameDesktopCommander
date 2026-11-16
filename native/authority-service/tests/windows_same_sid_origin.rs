//! T011-C4 Windows kernel-credential experiment. Not a broker or authorization grant.
//! Two unrelated child processes run under the same real Windows SID.
#![cfg(windows)]
use jdc_authority_service::windows_pipe_peer::{
    observe_client_sid_after_read, observe_process_sid,
};
use std::{
    os::windows::io::BorrowedHandle,
    process::{Child, Command, Stdio},
    ptr,
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    },
    Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        Threading::{CreateEventW, WaitForSingleObject},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
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
fn request(pipe: HANDLE, sent: u8, receive: bool) -> u8 {
    let mut written = 0u32;
    assert_ne!(
        unsafe { WriteFile(pipe, &sent, 1, &mut written, ptr::null_mut()) },
        0
    );
    assert_eq!(written, 1);
    if !receive {
        return 0;
    }
    let mut byte = 0u8;
    let mut count = 0u32;
    assert_ne!(
        unsafe { ReadFile(pipe, &mut byte, 1, &mut count, ptr::null_mut()) },
        0
    );
    assert_eq!(count, 1);
    byte
}

// A pending Windows IO operation owns its OVERLAPPED and byte buffer until
// completion, including error/cancellation paths. Never drop them on timeout.
fn complete_pending(pipe: HANDLE, event: HANDLE, ov: &OVERLAPPED) -> u32 {
    let status = unsafe { WaitForSingleObject(event, 7000) };
    if status != WAIT_OBJECT_0 {
        unsafe { CancelIoEx(pipe, ov) };
        let mut drained = 0u32;
        unsafe { GetOverlappedResult(pipe, ov, &mut drained, 1) };
        panic!("E_PIPE_ASYNC_IO_TIMEOUT");
    }
    let mut count = 0u32;
    assert_ne!(
        unsafe { GetOverlappedResult(pipe, ov, &mut count, 0) },
        0,
        "kernel overlapped I/O completion failed"
    );
    count
}

// The server created an overlapped pipe. Supplying NULL OVERLAPPED here
// could falsely report successful I/O, according to Win32 documentation.
fn server_byte_io(pipe: HANDLE, byte: &mut u8, reading: bool) {
    let event = Handle(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) });
    assert!(!event.0.is_null());
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = event.0;
    let completed = unsafe {
        if reading {
            ReadFile(pipe, byte, 1, ptr::null_mut(), &mut ov)
        } else {
            WriteFile(pipe, byte, 1, ptr::null_mut(), &mut ov)
        }
    };
    let transferred = if completed != 0 {
        let mut count = 0u32;
        assert_ne!(
            unsafe { GetOverlappedResult(pipe, &ov, &mut count, 0) },
            0,
            "completed I/O result must be observed"
        );
        count
    } else {
        assert_eq!(
            unsafe { GetLastError() },
            ERROR_IO_PENDING,
            "unexpected kernel I/O error"
        );
        complete_pending(pipe, event.0, &ov)
    };
    assert_eq!(transferred, 1, "exactly one real pipe byte is required");
}

#[test]
fn same_sid_child_connects_and_reads_reply() {
    let Ok(name) = std::env::var("JDC_T011_TEST_SAME_SID_PIPE") else {
        return;
    };
    let pipe_name = wide(&name);
    let raw = unsafe {
        CreateFileW(
            pipe_name.as_ptr(),
            0x0003,
            0,
            ptr::null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    assert_ne!(
        raw, INVALID_HANDLE_VALUE,
        "same-SID client failed to open pipe"
    );
    assert!(!raw.is_null());
    let pipe = Handle(raw);
    assert_eq!(request(pipe.0, b'R', true), b'A');
}

fn observe_independent_client(label: &str, unique: u128) -> (u32, Vec<u8>) {
    let name = format!(
        r"\\.\pipe\JDC-T011-SAMESID-{}-{unique}-{label}",
        std::process::id()
    );
    let wide_name = wide(&name);
    // The default process-token DACL intentionally gives the same real user
    // access. This models a client launched by an ordinary interactive user.
    let raw = unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            128,
            128,
            0,
            ptr::null(),
        )
    };
    assert_ne!(raw, INVALID_HANDLE_VALUE, "real pipe creation failed");
    assert!(!raw.is_null());
    let pipe = Handle(raw);
    let event = Handle(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) });
    assert!(!event.0.is_null());
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.0;
    let connected = unsafe { ConnectNamedPipe(pipe.0, &mut overlapped) };
    let error = if connected == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    assert!(
        connected != 0 || error == ERROR_IO_PENDING || error == ERROR_PIPE_CONNECTED,
        "unexpected kernel ConnectNamedPipe outcome: {error}"
    );

    let mut child = ChildCleanup(
        Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "same_sid_child_connects_and_reads_reply"])
            .env("JDC_T011_TEST_SAME_SID_PIPE", &name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("actual child OS process must be created"),
    );
    if error == ERROR_IO_PENDING {
        let _ = complete_pending(pipe.0, event.0, &overlapped);
    }
    // Impersonation consumes the exact connection that delivered this request.
    // The SID alone is identical for both independent child origins.
    let mut inbound = 0u8;
    server_byte_io(pipe.0, &mut inbound, true);
    assert_eq!(inbound, b'R');
    let observed = observe_client_sid_after_read(unsafe { BorrowedHandle::borrow_raw(pipe.0) })
        .expect("kernel-issued impersonation token after real request");
    let mut reply = b'A';
    server_byte_io(pipe.0, &mut reply, false);
    let child_pid = child.0.id();
    assert!(
        child
            .0
            .wait()
            .expect("child must terminate after reply")
            .success(),
        "independent client must complete IPC exchange"
    );
    (child_pid, observed)
}

#[test]
fn two_independent_processes_under_same_sid_are_not_provenance_distinguishable() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("valid epoch")
        .as_nanos();
    let parent_sid = observe_process_sid().expect("real process-token SID");
    let (legitimate_pid, legitimate_sid) = observe_independent_client("legit", unique);
    let (impostor_pid, impostor_sid) = observe_independent_client("impostor", unique);
    assert_ne!(
        legitimate_pid, impostor_pid,
        "fixture must use two processes"
    );
    assert_ne!(legitimate_pid, std::process::id());
    assert_ne!(impostor_pid, std::process::id());
    assert!(
        legitimate_sid == parent_sid,
        "first true kernel SID mismatch"
    );
    assert!(
        impostor_sid == parent_sid,
        "second true kernel SID mismatch"
    );
    // RED disproved: two real origins yield the same kernel-issued SID.
    // A SID-only broker would treat both as equally eligible. This test
    // grants neither process any file authority; production remains deny-only.
    assert!(
        legitimate_sid == impostor_sid,
        "SID alone cannot prove client origin"
    );
}
