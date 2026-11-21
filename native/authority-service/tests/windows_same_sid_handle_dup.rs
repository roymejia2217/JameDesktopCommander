//! T011-C4 non-shipping proof: ambient same-user process access can defeat
//! handle privacy even when the original event handle is non-inheritable.
//! Own child fixtures only. No privileged service, secret, or file access.
#![cfg(windows)]
use jdc_authority_service::{
    windows_pipe_peer::observe_process_sid, windows_process_custody::seal_process_owner_rights,
};
use std::{
    ffi::c_void,
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, Stdio},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DuplicateHandle, GetLastError, LocalFree, DUPLICATE_SAME_ACCESS,
        ERROR_ACCESS_DENIED, HANDLE, WAIT_OBJECT_0,
    },
    Security::{
        AdjustTokenPrivileges,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_KERNEL_OBJECT,
        },
        EqualSid, GetTokenInformation, SetKernelObjectSecurity, TokenOwner,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_OWNER, TOKEN_QUERY,
    },
    System::Threading::{
        CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, SetEvent,
        WaitForSingleObject, PROCESS_DUP_HANDLE,
    },
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct ChildCleanup(Child);
impl Drop for ChildCleanup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn process_sid_hex() -> String {
    observe_process_sid()
        .expect("kernel process token must be readable")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn verify_real_process_sid() {
    let expected = std::env::var("JDC_T011_EXPECTED_TEST_SID").expect("fixture SID expectation");
    assert!(
        process_sid_hex() == expected,
        "fixture must run under the real parent's Windows SID"
    );
}

#[test]
fn fixture_holds_uninheritable_event() {
    if std::env::var("JDC_T011_CHILD_HOLDS_EVENT").as_deref() != Ok("1") {
        return;
    }
    verify_real_process_sid();
    // SECURITY_ATTRIBUTES == NULL: this event handle is NOT inheritable.
    // Deliberately no event name or public namespace.
    let raw = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
    assert!(!raw.is_null(), "actual unnamed Windows event must exist");
    let event = Handle(raw);
    println!("JDC_T011_TEST_EVENT={}", event.0 as usize);
    std::io::stdout().flush().expect("emit fixture rendezvous");
    assert_eq!(
        unsafe { WaitForSingleObject(event.0, 8_000) },
        WAIT_OBJECT_0,
        "another process must actually signal the private event"
    );
}

#[test]
fn fixture_foreign_same_sid_duplicates_event() {
    if std::env::var("JDC_T011_CHILD_DUPLICATES_EVENT").as_deref() != Ok("1") {
        return;
    }
    verify_real_process_sid();
    let target_pid = std::env::var("JDC_T011_TARGET_PID")
        .expect("test-only child pid")
        .parse::<u32>()
        .expect("valid test PID");
    let handle_value = std::env::var("JDC_T011_TARGET_HANDLE")
        .expect("test-only known raw handle number")
        .parse::<usize>()
        .expect("valid fixture handle");
    assert_ne!(target_pid, std::process::id());
    // This is an independent process asking the OS to open the other child.
    let raw = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, target_pid) };
    assert!(
        !raw.is_null(),
        "foreign same-SID OpenProcess must be observed"
    );
    let source_process = Handle(raw);
    let mut duplicate: HANDLE = ptr::null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                source_process.0,
                handle_value as HANDLE,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        },
        0,
        "OS must actually duplicate the holder's private event"
    );
    assert!(!duplicate.is_null());
    let event = Handle(duplicate);
    assert_ne!(
        unsafe { SetEvent(event.0) },
        0,
        "real duplicate must signal object"
    );
}

#[test]
fn same_sid_private_handle_does_not_prove_client_custody() {
    let exe = std::env::current_exe().expect("real Rust test executable");
    let expected_sid = process_sid_hex();
    let mut holder = ChildCleanup(
        Command::new(&exe)
            .args([
                "--exact",
                "fixture_holds_uninheritable_event",
                "--nocapture",
            ])
            .env("JDC_T011_CHILD_HOLDS_EVENT", "1")
            .env("JDC_T011_EXPECTED_TEST_SID", &expected_sid)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("real event-holding child process"),
    );
    let holder_pid = holder.0.id();
    assert_ne!(holder_pid, std::process::id());
    let output = holder.0.stdout.take().expect("test-owned stdout");
    let mut reader = BufReader::new(output);
    let mut known_handle = None;
    // Rust's test harness emits its own preamble. Read only a bounded number
    // of lines; no polling and no action against unrelated processes.
    for _ in 0..12 {
        let mut line = String::new();
        if reader.read_line(&mut line).expect("fixture output") == 0 {
            break;
        }
        if let Some(value) = line.trim().strip_prefix("JDC_T011_TEST_EVENT=") {
            known_handle = Some(value.parse::<usize>().expect("numeric test handle"));
            break;
        }
    }
    let handle_value = known_handle.expect("child must disclose test-only handle number");
    let attacker_status = Command::new(&exe)
        .args([
            "--exact",
            "fixture_foreign_same_sid_duplicates_event",
            "--nocapture",
        ])
        .env("JDC_T011_CHILD_DUPLICATES_EVENT", "1")
        .env("JDC_T011_EXPECTED_TEST_SID", &expected_sid)
        .env("JDC_T011_TARGET_PID", holder_pid.to_string())
        .env("JDC_T011_TARGET_HANDLE", handle_value.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("independent adversarial child process");
    assert!(
        holder.0.wait().expect("event holder terminates").success(),
        "test event must have been signaled through a real duplicated handle"
    );
    // RED disproved: a second real same-SID process opened the event
    // holder with PROCESS_DUP_HANDLE, duplicated its *non-inheritable* handle
    // and signaled the original kernel object. No product privilege granted.
    // This proof supplies the handle value to the attacker deliberately;
    // it does not establish whether an attacker can discover unknown values.
    assert!(
        attacker_status.success(),
        "the real same-SID child must duplicate and signal the private event"
    );
}

const WRITE_DAC_RIGHT: u32 = 0x0004_0000;
const READ_CONTROL_RIGHT: u32 = 0x0002_0000;

struct LocalBuffer(*mut c_void);
impl Drop for LocalBuffer {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn own_sid_text() -> String {
    let sid = observe_process_sid().expect("actual process token SID");
    let mut ptr: *mut u16 = ptr::null_mut();
    assert_ne!(
        unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut ptr) },
        0,
        "real token SID converts to SDDL"
    );
    assert!(!ptr.is_null());
    let _buffer = LocalBuffer(ptr.cast());
    let length = (0..192)
        .find(|&i| unsafe { *ptr.add(i) } == 0)
        .expect("bounded kernel SID string");
    String::from_utf16(unsafe { std::slice::from_raw_parts(ptr, length) })
        .expect("kernel SID is valid UTF-16")
}

fn set_test_process_dacl(process: HANDLE, user_access: &str) {
    // Historical RED-proof baseline: owner retains implicit WRITE_DAC when
    // OWNER RIGHTS is absent. Do not change this adversarial control.
    let sddl = format!("D:P(A;;GA;;;SY)(A;;{user_access};;;{})", own_sid_text());
    let mut descriptor = ptr::null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(&sddl).as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        },
        0,
        "Win32 must parse actual test-only SDDL"
    );
    assert!(!descriptor.is_null());
    let _owner = LocalBuffer(descriptor);
    assert_ne!(
        unsafe { SetKernelObjectSecurity(process, DACL_SECURITY_INFORMATION, descriptor) },
        0,
        "Win32 must replace actual process DACL"
    );
}

#[test]
fn fixture_holds_restricted_process_dacl_event() {
    if std::env::var("JDC_T011_DACL_HOLDER").as_deref() != Ok("1") {
        return;
    }
    verify_real_process_sid();
    let raw = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
    assert!(!raw.is_null(), "real non-inheritable unnamed event");
    let event = Handle(raw);
    set_test_process_dacl(unsafe { GetCurrentProcess() }, "0x1000");
    println!("JDC_T011_DACL_EVENT={}", event.0 as usize);
    std::io::stdout().flush().expect("test handshake");
    assert_eq!(
        unsafe { WaitForSingleObject(event.0, 8_000) },
        WAIT_OBJECT_0,
        "actual event must be signaled through a forged process DACL"
    );
}

#[test]
fn fixture_same_sid_foreign_process_changes_dacl() {
    if std::env::var("JDC_T011_DACL_ATTACKER").as_deref() != Ok("1") {
        return;
    }
    verify_real_process_sid();

    disable_attacker_token_privileges();
    let pid = std::env::var("JDC_T011_DACL_PID")
        .expect("test-owned target PID")
        .parse::<u32>()
        .expect("numeric test PID");
    let event_handle = std::env::var("JDC_T011_DACL_HANDLE")
        .expect("test-only event number")
        .parse::<usize>()
        .expect("numeric handle");
    assert_ne!(pid, std::process::id());
    assert_attacker_is_target_process_owner(pid);
    let initially_denied = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
    assert!(
        initially_denied.is_null(),
        "restricted process DACL must first reject PROCESS_DUP_HANDLE"
    );
    assert_eq!(
        unsafe { GetLastError() },
        ERROR_ACCESS_DENIED,
        "initial denial must be a real Win32 access-denied error"
    );
    let dacl_handle = unsafe { OpenProcess(WRITE_DAC_RIGHT, 0, pid) };
    // RED hypothesis: same-SID attacker cannot change a restrictive DACL.
    assert!(
        !dacl_handle.is_null(),
        "same-SID attacker retained WRITE_DAC after actual DUP_HANDLE denial"
    );
    // GREEN: The second same-SID process can modify the restricted DACL
    // using the owner's implicit WRITE_DAC right, and then duplicate an
    // existing non-inheritable handle given its test-only numeric value.
    // Never aim at an unrelated process or an installed JDC service.
    let process_dacl = Handle(dacl_handle);
    set_test_process_dacl(process_dacl.0, "GA");
    let raw = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
    assert!(!raw.is_null(), "changed DACL must now allow duplication");
    let target_process = Handle(raw);
    let mut duplicate = ptr::null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                target_process.0,
                event_handle as HANDLE,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        },
        0,
        "Win32 must duplicate real test event"
    );
    assert!(!duplicate.is_null());
    let event = Handle(duplicate);
    assert_ne!(unsafe { SetEvent(event.0) }, 0);
}

#[test]
fn same_sid_owner_write_dac_can_undo_restricted_process_dacl() {
    let exe = std::env::current_exe().expect("existing Rust test executable");
    let sid = process_sid_hex();
    let mut holder = ChildCleanup(
        Command::new(&exe)
            .args([
                "--exact",
                "fixture_holds_restricted_process_dacl_event",
                "--nocapture",
            ])
            .env("JDC_T011_DACL_HOLDER", "1")
            .env("JDC_T011_EXPECTED_TEST_SID", &sid)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("real test holder child"),
    );
    let pid = holder.0.id();
    assert_ne!(pid, std::process::id());
    let reader = holder.0.stdout.take().expect("event handshake stream");
    let mut input = BufReader::new(reader);
    let mut test_handle = None;

    for _ in 0..12 {
        let mut line = String::new();
        if input.read_line(&mut line).expect("child handshake") == 0 {
            break;
        }
        if let Some(value) = line.trim().strip_prefix("JDC_T011_DACL_EVENT=") {
            test_handle = Some(value.parse::<usize>().expect("fixture handle number"));
            break;
        }
    }
    let event = test_handle.expect("real restricted child must create event");
    let result = Command::new(&exe)
        .args([
            "--exact",
            "fixture_same_sid_foreign_process_changes_dacl",
            "--nocapture",
        ])
        .env("JDC_T011_DACL_ATTACKER", "1")
        .env("JDC_T011_EXPECTED_TEST_SID", &sid)
        .env("JDC_T011_DACL_PID", pid.to_string())
        .env("JDC_T011_DACL_HANDLE", event.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("real independent same-SID attacker child");
    assert!(
        result.status.success(),
        "attacker fixture failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        holder.0.wait().expect("holder finishes").success(),
        "original owner event signaled via duplicated handle"
    );
}

// Independent disposable-process acceptance for Windows OWNER RIGHTS
// (S-1-3-4). This is NOT a broker, issuer or trusted MCP launcher.
#[test]
fn fixture_owner_rights_holder_keeps_event_private() {
    if std::env::var("JDC_T011_OWNER_RIGHTS_HOLDER").as_deref() != Ok("1") {
        return;
    }
    verify_real_process_sid();
    let raw = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
    assert!(!raw.is_null(), "test-only event creation");
    let event = Handle(raw);
    // Exercise a real kernel process HANDLE carrying READ_CONTROL|WRITE_DAC,
    // as a trusted launcher would retain after creating its suspended child.
    let process =
        Handle(unsafe { OpenProcess(READ_CONTROL_RIGHT | WRITE_DAC_RIGHT, 0, std::process::id()) });
    assert!(
        !process.0.is_null(),
        "test must own a real writable process handle"
    );
    seal_process_owner_rights(unsafe {
        std::os::windows::io::BorrowedHandle::borrow_raw(process.0)
    })
    .expect("kernel-derived OWNER RIGHTS process DACL");
    // Do not retain an open WRITE_DAC handle in the client-side fixture.
    drop(process);
    println!("JDC_T011_OWNER_RIGHTS_EVENT={}", event.0 as usize);
    std::io::stdout().flush().expect("test holder rendezvous");

    let mut release = [0_u8; 1];
    std::io::stdin()
        .read_exact(&mut release)
        .expect("bounded parent release");
    assert_eq!(release, [0x51]);
    assert_eq!(
        unsafe { WaitForSingleObject(event.0, 0) },
        windows_sys::Win32::Foundation::WAIT_TIMEOUT,
        "the private event must not have been signaled by an impostor"
    );
}

#[test]
fn fixture_owner_rights_intruder_is_denied() {
    if std::env::var("JDC_T011_OWNER_RIGHTS_ATTACKER").as_deref() != Ok("1") {
        return;
    }
    verify_real_process_sid();
    // Scope token changes to the disposable adversary child only.
    disable_attacker_token_privileges();
    let pid = std::env::var("JDC_T011_OWNER_RIGHTS_PID")
        .expect("test-only child PID")
        .parse::<u32>()
        .expect("numeric test-owned PID");
    assert_ne!(pid, std::process::id());
    assert_attacker_is_target_process_owner(pid);

    for (right, label) in [
        (PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE"),
        (WRITE_DAC_RIGHT, "WRITE_DAC"),
        (0x0008_0000, "WRITE_OWNER"),
    ] {
        let opened = unsafe { OpenProcess(right, 0, pid) };
        if !opened.is_null() {
            unsafe { CloseHandle(opened) };
        }
        assert!(
            opened.is_null(),
            "same-owner impostor unexpectedly obtained {label}"
        );
        assert_eq!(
            unsafe { GetLastError() },
            ERROR_ACCESS_DENIED,
            "real kernel denial required for {label}"
        );
    }
    println!("T011_WINDOWS_SAME_OWNER_PROCESS_RIGHTS_DENIED");
}

#[test]
fn owner_rights_acl_prevents_same_sid_process_permission_takeover() {
    let exe = std::env::current_exe().expect("test binary");
    let sid = process_sid_hex();
    let mut holder = ChildCleanup(
        Command::new(&exe)
            .args([
                "--exact",
                "fixture_owner_rights_holder_keeps_event_private",
                "--nocapture",
            ])
            .env("JDC_T011_OWNER_RIGHTS_HOLDER", "1")
            .env("JDC_T011_EXPECTED_TEST_SID", &sid)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("independent event holder"),
    );
    let pid = holder.0.id();
    let stdout = holder.0.stdout.take().expect("holder event rendezvous");
    let mut stream = BufReader::new(stdout);
    let mut observed_handle = false;
    for _ in 0..12 {
        let mut line = String::new();
        if stream.read_line(&mut line).expect("test fixture output") == 0 {
            break;
        }
        if let Some(value) = line.trim().strip_prefix("JDC_T011_OWNER_RIGHTS_EVENT=") {
            let _event = value.parse::<usize>().expect("test-only event identity");
            observed_handle = true;
            break;
        }
    }
    assert!(observed_handle, "actual target must hold its own event");
    let intruder = Command::new(&exe)
        .args([
            "--exact",
            "fixture_owner_rights_intruder_is_denied",
            "--nocapture",
        ])
        .env("JDC_T011_OWNER_RIGHTS_ATTACKER", "1")
        .env("JDC_T011_EXPECTED_TEST_SID", &sid)
        .env("JDC_T011_OWNER_RIGHTS_PID", pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("separate same-owner process");
    holder
        .0
        .stdin
        .take()
        .expect("event-controlled release channel")
        .write_all(&[0x51])
        .expect("release original event holder");
    let held = holder.0.wait().expect("holder exit after release");
    assert!(
        intruder.status.success(),
        "same-owner denial proof failed: {}",
        String::from_utf8_lossy(&intruder.stderr)
    );
    assert!(
        String::from_utf8_lossy(&intruder.stdout)
            .contains("T011_WINDOWS_SAME_OWNER_PROCESS_RIGHTS_DENIED"),
        "adversary must execute and report real kernel denials"
    );
    assert!(
        held.success(),
        "original private event must remain unsignaled"
    );
}

fn disable_attacker_token_privileges() {
    // Only the disposable attacker subprocess changes its own token.
    // The host, parent process, services and other tokens are untouched.
    let mut raw = ptr::null_mut();
    assert_ne!(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut raw,
            )
        },
        0,
        "attacker must own its actual process token"
    );
    let token = Handle(raw);
    assert_ne!(
        unsafe {
            AdjustTokenPrivileges(token.0, 1, ptr::null(), 0, ptr::null_mut(), ptr::null_mut())
        },
        0,
        "real Win32 privilege removal must succeed"
    );
}

fn assert_attacker_is_target_process_owner(pid: u32) {
    // Compare two independently kernel-observed owners, not self-reported
    // names or SIDs supplied through the fixture's environment.
    let raw = unsafe { OpenProcess(READ_CONTROL_RIGHT, 0, pid) };
    assert!(!raw.is_null(), "owner must retain READ_CONTROL");
    let owner_query = Handle(raw);
    let mut actual_owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                owner_query.0,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut actual_owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        },
        0,
        "kernel must report the real target process owner"
    );

    assert!(!descriptor.is_null());
    assert!(!actual_owner.is_null());
    let _descriptor_owner = LocalBuffer(descriptor);
    let mut own_token = ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut own_token) },
        0
    );
    let token = Handle(own_token);
    let mut required = 0u32;
    assert_eq!(
        unsafe { GetTokenInformation(token.0, TokenOwner, ptr::null_mut(), 0, &mut required) },
        0
    );
    assert!(required as usize >= std::mem::size_of::<TOKEN_OWNER>());
    assert!(required <= 4096, "bounded Win32 token-owner info");
    let mut storage = vec![0u8; required as usize];
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenOwner,
                storage.as_mut_ptr().cast(),
                storage.len() as u32,
                &mut required,
            )
        },
        0,
        "kernel must report attacker's token default owner"
    );

    let token_owner = unsafe { ptr::read_unaligned(storage.as_ptr().cast::<TOKEN_OWNER>()) };
    assert!(!token_owner.Owner.is_null());
    assert_ne!(
        unsafe { EqualSid(actual_owner, token_owner.Owner) },
        0,
        "target process owner SID must match the attacker's actual token owner"
    );
}
