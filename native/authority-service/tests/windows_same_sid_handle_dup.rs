//! T011-C4 non-shipping proof: ambient same-user process access can defeat
//! handle privacy even when the original event handle is non-inheritable.
//! Own child fixtures only. No privileged service, secret, or file access.
#![cfg(windows)]
use jdc_authority_service::windows_pipe_peer::observe_process_sid;
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, WAIT_OBJECT_0},
    System::Threading::{
        CreateEventW, GetCurrentProcess, OpenProcess, SetEvent, WaitForSingleObject,
        PROCESS_DUP_HANDLE,
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
