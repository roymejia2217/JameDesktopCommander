//! CI-only experiment, used solely by the nonshipping SCM proof binary.
//! The protected handoff file is a fixture rendezvous, NOT production IPC.
use jdc_authority_service::{
    windows_creation_custody::seal_current_scm_fixture_issuer,
    windows_issued_client::IssuedClient,
    windows_token::{
        verify_scm_fixture_identity, verify_scm_fixture_process_identity, ScmFixtureRole,
    },
    IdentityDenied,
};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    path::PathBuf,
    sync::mpsc::Receiver,
    time::Duration,
};
use windows_service::{
    service::{
        ServiceAccess, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::ServiceStatusHandle,
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED, FILETIME, WAIT_TIMEOUT},
    Storage::FileSystem::SYNCHRONIZE,
    System::Threading::{
        GetProcessId, GetProcessTimes, OpenProcess, OpenThread, TerminateProcess,
        WaitForSingleObject, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_OPERATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
        THREAD_SUSPEND_RESUME, THREAD_TERMINATE,
    },
};
const OBSERVE_ACCESS: u32 = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    pid: u32,
    creation: u64,
}
impl Stamp {
    fn capture(process: BorrowedHandle<'_>) -> Result<Self, IdentityDenied> {
        let raw = process.as_raw_handle();
        let pid = unsafe { GetProcessId(raw) };
        let (mut creation, mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        if pid == 0
            || unsafe { WaitForSingleObject(raw, 0) } != WAIT_TIMEOUT
            || unsafe { GetProcessTimes(raw, &mut creation, &mut exit, &mut kernel, &mut user) }
                == 0
        {
            return Err(IdentityDenied);
        }
        let creation = u64::from(creation.dwHighDateTime) << 32 | u64::from(creation.dwLowDateTime);
        if creation == 0 || unsafe { WaitForSingleObject(raw, 0) } != WAIT_TIMEOUT {
            return Err(IdentityDenied);
        }
        Ok(Self { pid, creation })
    }
    fn verify(self, process: BorrowedHandle<'_>) -> Result<(), IdentityDenied> {
        if Self::capture(process)? != self {
            return Err(IdentityDenied);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Handoff {
    issuer: Stamp,
    child: Stamp,
    thread: u32,
}
impl Handoff {
    fn encode(self) -> String {
        format!(
            "JDC1\n{}\n{}\n{}\n{}\n{}\n",
            self.issuer.pid, self.issuer.creation, self.child.pid, self.child.creation, self.thread
        )
    }
    fn parse(text: &str) -> Result<Self, IdentityDenied> {
        let fields: Vec<_> = text.lines().collect();
        let ["JDC1", issuer, issuer_creation, child, child_creation, thread] = fields.as_slice()
        else {
            return Err(IdentityDenied);
        };
        let result = Self {
            issuer: Stamp {
                pid: issuer.parse().map_err(|_| IdentityDenied)?,
                creation: issuer_creation.parse().map_err(|_| IdentityDenied)?,
            },
            child: Stamp {
                pid: child.parse().map_err(|_| IdentityDenied)?,
                creation: child_creation.parse().map_err(|_| IdentityDenied)?,
            },
            thread: thread.parse().map_err(|_| IdentityDenied)?,
        };
        if result.issuer.pid == 0
            || result.child.pid == 0
            || result.thread == 0
            || result.issuer.pid == result.child.pid
            || result.issuer.creation == 0
            || result.child.creation < result.issuer.creation
            || result.encode() != text
        {
            return Err(IdentityDenied);
        }
        Ok(result)
    }
}

fn fixture_path() -> Result<PathBuf, IdentityDenied> {
    let exe = std::env::current_exe().map_err(|_| IdentityDenied)?;
    Ok(exe
        .parent()
        .ok_or(IdentityDenied)?
        .join("handoff")
        .join("issued-process.txt"))
}

fn open_observer_pin(stamp: Stamp) -> Result<OwnedHandle, IdentityDenied> {
    // PID is a locator from the protected issuer, never an authority grant.
    let raw = unsafe { OpenProcess(OBSERVE_ACCESS, 0, stamp.pid) };
    if raw.is_null() {
        return Err(IdentityDenied);
    }
    let pin = unsafe { OwnedHandle::from_raw_handle(raw) };
    // The issuer checks its child's primary token with the original handle.
    // The observer must not require cross-account OpenProcessToken or SeDebug.
    stamp.verify(pin.as_handle())?;
    Ok(pin)
}

fn denied_process_rights(pid: u32) -> Result<(), IdentityDenied> {
    for access in [
        PROCESS_DUP_HANDLE,
        PROCESS_CREATE_THREAD,
        PROCESS_TERMINATE,
        PROCESS_VM_READ,
        PROCESS_VM_WRITE,
        PROCESS_VM_OPERATION,
        0x0004_0000,
        0x0008_0000,
    ] {
        let raw = unsafe { OpenProcess(access, 0, pid) };
        let error = unsafe { GetLastError() };
        if !raw.is_null() {
            unsafe { CloseHandle(raw) };
            return Err(IdentityDenied);
        }
        if error != ERROR_ACCESS_DENIED {
            return Err(IdentityDenied);
        }
    }
    Ok(())
}
fn denied_thread_rights(tid: u32) -> Result<(), IdentityDenied> {
    for access in [
        THREAD_GET_CONTEXT,
        THREAD_SET_CONTEXT,
        THREAD_SUSPEND_RESUME,
        THREAD_TERMINATE,
        0x0004_0000,
        0x0008_0000,
    ] {
        let raw = unsafe { OpenThread(access, 0, tid) };
        let error = unsafe { GetLastError() };
        if !raw.is_null() {
            unsafe { CloseHandle(raw) };
            return Err(IdentityDenied);
        }
        if error != ERROR_ACCESS_DENIED {
            return Err(IdentityDenied);
        }
    }
    Ok(())
}

pub fn issue(handler: &ServiceStatusHandle, stop: Receiver<()>) -> Result<(), IdentityDenied> {
    verify_scm_fixture_identity(ScmFixtureRole::Issuer).map_err(|_| IdentityDenied)?;
    seal_current_scm_fixture_issuer()?;
    let path = fixture_path()?;
    let child_image = path
        .parent()
        .and_then(|p| p.parent())
        .ok_or(IdentityDenied)?
        .join("jdc-authority-scm-issued-client.exe");
    let mut command = OsString::from("\"");
    command.push(child_image.as_os_str());
    command.push(OsStr::new("\""));
    let system = std::env::var("SystemRoot").map_err(|_| IdentityDenied)?;
    let child = IssuedClient::launch_scm_observable_fixture(
        &child_image,
        &command,
        &[("SystemRoot", &system)],
    )?;
    verify_scm_fixture_process_identity(ScmFixtureRole::Issuer, child.process_handle())
        .map_err(|_| IdentityDenied)?;
    if verify_scm_fixture_process_identity(ScmFixtureRole::Authority, child.process_handle())
        .is_ok()
    {
        return Err(IdentityDenied);
    }
    let current = unsafe {
        BorrowedHandle::borrow_raw(windows_sys::Win32::System::Threading::GetCurrentProcess())
    };
    let handoff = Handoff {
        issuer: Stamp::capture(current)?,
        child: Stamp::capture(child.process_handle())?,
        thread: child.tid(),
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| IdentityDenied)?;
    file.write_all(handoff.encode().as_bytes())
        .map_err(|_| IdentityDenied)?;
    file.sync_all().map_err(|_| IdentityDenied)?;
    drop(file);
    // RUNNING signals a bounded fixture rendezvous only. The separate
    // deny-only SCM production candidate is untouched; there is no broker.
    handler
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        })
        .map_err(|_| IdentityDenied)?;
    stop.recv_timeout(Duration::from_secs(45))
        .map_err(|_| IdentityDenied)?;
    // The suspended proof child is never executed. Require exact cleanup.
    if unsafe { TerminateProcess(child.process_handle().as_raw_handle(), 1) } == 0 {
        return Err(IdentityDenied);
    }
    child.wait_for_exit(Duration::from_secs(5))?;
    if child.exit_code()? != 1 {
        return Err(IdentityDenied);
    }
    Ok(())
}

pub fn observe() -> Result<(), IdentityDenied> {
    verify_scm_fixture_identity(ScmFixtureRole::Authority).map_err(|_| IdentityDenied)?;
    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .map_err(|_| IdentityDenied)?;
    let service = manager
        .open_service(
            ScmFixtureRole::Issuer.service_name(),
            ServiceAccess::QUERY_STATUS,
        )
        .map_err(|_| IdentityDenied)?;
    let record = fixture_path()?;
    // A successful read-only pin must not imply writable attestation state.
    match OpenOptions::new().write(true).open(&record) {
        Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {}
        _ => return Err(IdentityDenied),
    }
    let mut text = String::new();
    File::open(record)
        .map_err(|_| IdentityDenied)?
        .take(129)
        .read_to_string(&mut text)
        .map_err(|_| IdentityDenied)?;
    if text.len() > 128 {
        return Err(IdentityDenied);
    }
    let handoff = Handoff::parse(&text)?;
    let status = service.query_status().map_err(|_| IdentityDenied)?;
    if status.current_state != ServiceState::Running
        || status.process_id != Some(handoff.issuer.pid)
    {
        return Err(IdentityDenied);
    }
    let issuer = open_observer_pin(handoff.issuer)?;
    let child = open_observer_pin(handoff.child)?;
    // A stale creation stamp must not authorize a real live PID.
    if open_observer_pin(Stamp {
        creation: handoff.child.creation ^ 1,
        ..handoff.child
    })
    .is_ok()
    {
        return Err(IdentityDenied);
    }
    denied_process_rights(handoff.issuer.pid)?;
    denied_process_rights(handoff.child.pid)?;
    denied_thread_rights(handoff.thread)?;
    handoff.issuer.verify(issuer.as_handle())?;
    handoff.child.verify(child.as_handle())?;
    let status = service.query_status().map_err(|_| IdentityDenied)?;
    if status.current_state != ServiceState::Running
        || status.process_id != Some(handoff.issuer.pid)
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handoff_rejects_ambiguous_or_invalid_locators() {
        let valid = "JDC1\n10\n100\n20\n101\n30\n";
        assert_eq!(Handoff::parse(valid).unwrap().encode(), valid);
        for bad in [
            "JDC1\n10\n100\n10\n101\n30\n",
            "JDC1\n10\n100\n20\n99\n30\n",
            "JDC1\n0\n100\n20\n101\n30\n",
            "JDC1\n10\n100\n20\n101\n0\n",
            "JDC1\n010\n100\n20\n101\n30\n",
            "JDC1\n10\n100\n20\n101\n30\nextra\n",
        ] {
            assert!(Handoff::parse(bad).is_err());
        }
    }
    #[test]
    fn kernel_stamp_rejects_wrong_creation_identity() {
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let process = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) };
        let stamp = Stamp::capture(process).unwrap();
        stamp.verify(process).unwrap();
        assert!(Stamp {
            creation: stamp.creation ^ 1,
            ..stamp
        }
        .verify(process)
        .is_err());
        assert!(Stamp { pid: 0, ..stamp }.verify(process).is_err());
    }

    #[test]
    fn retained_process_object_denies_stamp_after_child_exits() {
        let image = std::env::current_exe().unwrap();
        let command = format!("\"{}\"", image.display());
        let system = std::env::var("SystemRoot").unwrap();
        let child = IssuedClient::launch_suspended(
            &image,
            OsStr::new(&command),
            &[("SystemRoot", &system)],
        )
        .unwrap();
        let pin = child.process_handle().try_clone_to_owned().unwrap();
        let stamp = Stamp::capture(pin.as_handle()).unwrap();
        assert_eq!(stamp.pid, child.pid());
        drop(child);
        assert!(stamp.verify(pin.as_handle()).is_err());
    }

    #[test]
    fn ordinary_process_cannot_issue_observable_scm_child() {
        let image = std::env::current_exe().unwrap();
        let command = format!("\"{}\"", image.display());
        let system = std::env::var("SystemRoot").unwrap();
        assert!(IssuedClient::launch_scm_observable_fixture(
            &image,
            OsStr::new(&command),
            &[("SystemRoot", &system)]
        )
        .is_err());
    }
}
