//! Non-shipping Windows CREATE_SUSPENDED acceptance against real process
//! and thread kernel objects. This fixture is NOT a trusted launcher or
//! an MCP client-origin attestation. It only touches its own test children.
#![cfg(windows)]
use jdc_authority_service::{
    windows_creation_custody::OwnerRightsCreationDescriptors,
    windows_pipe_peer::observe_process_sid,
};
use std::{
    os::windows::ffi::OsStrExt,
    os::windows::io::BorrowedHandle,
    process::{Command, Stdio},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        AdjustTokenPrivileges, DuplicateToken, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_DUPLICATE, TOKEN_QUERY,
    },
    System::Threading::{
        CreateProcessW, GetCurrentProcess, GetExitCodeProcess, OpenProcess, OpenProcessToken,
        OpenThread, ResumeThread, TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW,
        CREATE_SUSPENDED, PROCESS_DUP_HANDLE, PROCESS_INFORMATION, STARTUPINFOW,
        THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME, THREAD_TERMINATE,
    },
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct TestChild {
    process: Handle,
    thread: Handle,
    pid: u32,
    tid: u32,
}
impl Drop for TestChild {
    fn drop(&mut self) {
        if unsafe { WaitForSingleObject(self.process.0, 0) } != WAIT_OBJECT_0 {
            unsafe { TerminateProcess(self.process.0, 1) };
            unsafe { WaitForSingleObject(self.process.0, 5_000) };
        }
    }
}

fn hex_sid() -> String {
    observe_process_sid()
        .expect("actual kernel token SID")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn unicode(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}
fn create_test_child_suspended(protected_at_creation: bool) -> TestChild {
    let exe = std::env::current_exe().expect("real test executable");
    let app = unicode(exe.as_os_str());
    let descriptors = if protected_at_creation {
        let mut raw_token = ptr::null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) },
            0,
            "the test issuer must hold a real primary process token"
        );
        let token = Handle(raw_token);
        Some(
            OwnerRightsCreationDescriptors::from_primary_token(unsafe {
                BorrowedHandle::borrow_raw(token.0)
            })
            .expect("kernel token owner must be available before process creation"),
        )
    } else {
        None
    };
    let process_attrs = descriptors.as_ref().map(|value| value.process_attributes());
    let thread_attrs = descriptors
        .as_ref()
        .map(|value| value.primary_thread_attributes());
    let cmd = format!(
        "\"{}\" --exact fixture_suspended_child --nocapture",
        exe.display()
    );
    let mut arguments = unicode(std::ffi::OsStr::new(&cmd));
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let created = unsafe {
        CreateProcessW(
            app.as_ptr(),
            arguments.as_mut_ptr(),
            process_attrs.as_ref().map_or(ptr::null(), |value| value),
            thread_attrs.as_ref().map_or(ptr::null(), |value| value),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            ptr::null(),
            ptr::null(),
            &startup,
            &mut info,
        )
    };
    assert_ne!(created, 0, "test child must be created by Win32");
    assert!(!info.hProcess.is_null() && !info.hThread.is_null());
    assert_ne!(info.dwProcessId, std::process::id());
    TestChild {
        process: Handle(info.hProcess),
        thread: Handle(info.hThread),
        pid: info.dwProcessId,
        tid: info.dwThreadId,
    }
}

fn disable_attacker_privileges() {
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
}

#[test]
fn creation_attributes_reject_an_actual_impersonation_token() {
    let mut token = ptr::null_mut();
    assert_ne!(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut token,
            )
        },
        0,
        "real primary process token"
    );
    let primary = Handle(token);
    let mut duplicate = ptr::null_mut();
    assert_ne!(
        unsafe { DuplicateToken(primary.0, SecurityImpersonation, &mut duplicate) },
        0,
        "actual impersonation token conversion"
    );
    let impersonation = Handle(duplicate);
    assert!(
        OwnerRightsCreationDescriptors::from_primary_token(unsafe {
            BorrowedHandle::borrow_raw(impersonation.0)
        })
        .is_err(),
        "impersonation token cannot be accepted as a child primary token"
    );
}

#[test]
fn fixture_suspended_child() {
    // The test harness can execute this fixture independently; a real
    // suspended process exits normally only after ResumeThread.
}

#[test]
fn fixture_same_sid_attacker_opens_thread() {
    let Ok(raw_tid) = std::env::var("JDC_T011_TARGET_THREAD_ID") else {
        return;
    };
    assert_eq!(hex_sid(), std::env::var("JDC_T011_EXPECTED_SID").unwrap());
    disable_attacker_privileges();
    let tid: u32 = raw_tid.parse().expect("test-only TID");
    let pid: u32 = std::env::var("JDC_T011_TARGET_PROCESS_ID")
        .expect("test-only PID")
        .parse()
        .expect("numeric PID");
    for (right, label) in [
        (PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE"),
        (0x0004_0000, "PROCESS_WRITE_DAC"),
        (0x0008_0000, "PROCESS_WRITE_OWNER"),
    ] {
        let opened = unsafe { OpenProcess(right, 0, pid) };
        let error = unsafe { GetLastError() };
        if !opened.is_null() {
            unsafe { CloseHandle(opened) };
        }
        assert!(
            opened.is_null(),
            "same-SID impostor opened {label} on protected process"
        );
        assert_eq!(
            error, ERROR_ACCESS_DENIED,
            "process kernel denial for {label}"
        );
    }
    for (right, label) in [
        (THREAD_SET_CONTEXT, "THREAD_SET_CONTEXT"),
        (THREAD_GET_CONTEXT, "THREAD_GET_CONTEXT"),
        (THREAD_TERMINATE, "THREAD_TERMINATE"),
        (THREAD_SUSPEND_RESUME, "THREAD_SUSPEND_RESUME"),
        (0x0004_0000, "THREAD_WRITE_DAC"),
        (0x0008_0000, "THREAD_WRITE_OWNER"),
    ] {
        let opened = unsafe { OpenThread(right, 0, tid) };
        let error = unsafe { GetLastError() };
        if !opened.is_null() {
            unsafe { CloseHandle(opened) };
        }
        assert!(
            opened.is_null(),
            "same-SID impostor opened {label} on suspended thread"
        );
        assert_eq!(
            error, ERROR_ACCESS_DENIED,
            "kernel access check for {label}"
        );
    }
}

#[test]
fn fixture_same_sid_exposes_default_child_handles() {
    let Ok(raw_pid) = std::env::var("JDC_T011_UNSEALED_PROCESS") else {
        return;
    };
    assert_eq!(hex_sid(), std::env::var("JDC_T011_EXPECTED_SID").unwrap());
    disable_attacker_privileges();
    let pid: u32 = raw_pid.parse().expect("test-owned process PID");
    let tid: u32 = std::env::var("JDC_T011_UNSEALED_THREAD")
        .expect("test-owned thread ID")
        .parse()
        .expect("numeric TID");
    for (handle, label) in [
        (
            unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) },
            "PROCESS_DUP_HANDLE",
        ),
        (
            unsafe { OpenThread(THREAD_SET_CONTEXT, 0, tid) },
            "THREAD_SET_CONTEXT",
        ),
    ] {
        assert!(
            !handle.is_null(),
            "unsealed test child unexpectedly denied {label}"
        );
        unsafe { CloseHandle(handle) };
    }
}

#[test]
fn default_suspended_creation_exposes_both_kernel_objects_to_same_sid() {
    let child = create_test_child_suspended(false);
    assert_eq!(
        unsafe { WaitForSingleObject(child.process.0, 0) },
        WAIT_TIMEOUT
    );
    let attacker = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "fixture_same_sid_exposes_default_child_handles",
            "--nocapture",
        ])
        .env("JDC_T011_UNSEALED_PROCESS", child.pid.to_string())
        .env("JDC_T011_UNSEALED_THREAD", child.tid.to_string())
        .env("JDC_T011_EXPECTED_SID", hex_sid())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("independent same-SID attacker");
    assert!(
        attacker.status.success(),
        "default Windows DACL attack not reproduced: {}",
        String::from_utf8_lossy(&attacker.stderr)
    );
    // Opening these handles during a post-create/pre-seal interval would
    // remain dangerous even if later DACL edits denied fresh OpenProcess.
    assert_eq!(unsafe { ResumeThread(child.thread.0) }, 1);
    assert_eq!(
        unsafe { WaitForSingleObject(child.process.0, 8_000) },
        WAIT_OBJECT_0
    );
}

#[test]
fn suspended_client_thread_is_not_reopenable_by_same_sid_impostor() {
    let child = create_test_child_suspended(true);
    assert_eq!(
        unsafe { WaitForSingleObject(child.process.0, 0) },
        WAIT_TIMEOUT,
        "the child must remain suspended before the authorization gate"
    );
    // Both kernel objects received the protected DACL AT CREATION: there
    // was no open-before-seal interval for a same-SID impostor to race.
    assert_ne!(child.tid, 0);
    let attacker = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "fixture_same_sid_attacker_opens_thread",
            "--nocapture",
        ])
        .env("JDC_T011_TARGET_THREAD_ID", child.tid.to_string())
        .env("JDC_T011_TARGET_PROCESS_ID", child.pid.to_string())
        .env("JDC_T011_EXPECTED_SID", hex_sid())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("independent same-SID process");
    assert!(
        attacker.status.success(),
        "thread custody failed: {}",
        String::from_utf8_lossy(&attacker.stderr)
    );
    assert_eq!(
        unsafe { ResumeThread(child.thread.0) },
        1,
        "only one suspended primary thread should be resumed"
    );
    assert_eq!(
        unsafe { WaitForSingleObject(child.process.0, 8_000) },
        WAIT_OBJECT_0
    );
    let mut code = u32::MAX;
    assert_ne!(unsafe { GetExitCodeProcess(child.process.0, &mut code) }, 0);
    assert_eq!(code, 0, "test-only child must execute after resume");
    // Avoid any implicit trusted origin assertion: the parent here is a
    // same-interactive-user test runner, not an OS-protected broker.
    assert_ne!(child.pid, std::process::id());
}
