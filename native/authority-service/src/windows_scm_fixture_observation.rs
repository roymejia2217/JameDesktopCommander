//! CI-only experiment, used solely by the nonshipping SCM proof binary.
//! The protected handoff file is a fixture rendezvous, NOT production IPC.
use jdc_authority_service::{
    windows_creation_custody::seal_current_scm_fixture_issuer,
    windows_issued_client::{IssuedClient, ThreadIdentity},
    windows_token::{
        verify_scm_fixture_identity, verify_scm_fixture_process_identity, ScmFixtureRole,
    },
    IdentityDenied,
};
use std::{
    cell::Cell,
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
        Service, ServiceAccess, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
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
        PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_DIRECT_IMPERSONATION, THREAD_GET_CONTEXT,
        THREAD_IMPERSONATE, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION,
        THREAD_SET_CONTEXT, THREAD_SET_INFORMATION, THREAD_SET_LIMITED_INFORMATION,
        THREAD_SET_THREAD_TOKEN, THREAD_SUSPEND_RESUME, THREAD_TERMINATE,
    },
};
const OBSERVE_ACCESS: u32 = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum JobProofMode {
    Observe,
    Resume,
    SdkRead,
}
impl JobProofMode {
    fn record(self, observer: &str, resume: &str, sdk: &str) -> PathBuf {
        PathBuf::from(match self {
            Self::Observe => observer,
            Self::Resume => resume,
            Self::SdkRead => sdk,
        })
    }
    fn suffix(self) -> &'static str {
        match self {
            Self::Observe => "",
            Self::Resume => "-resume",
            Self::SdkRead => "-sdk-read",
        }
    }
    fn allows_resume(self) -> bool {
        self != Self::Observe
    }
    pub fn observer_success(self) -> u32 {
        match self {
            Self::Observe => 8,
            Self::Resume => 12,
            Self::SdkRead => 16,
        }
    }
    pub fn issuer_success(self) -> u32 {
        match self {
            Self::Observe => 10,
            Self::Resume => 14,
            Self::SdkRead => 18,
        }
    }
}

// Fixed nonshipping SCM service-specific denial codes. Never contain paths,
// credentials, kernel handles, or untrusted error text. Observer-only
// success remains 8/10; resume uses 12/14; SDK read uses 16/18.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ProofPhase {
    ObserverInitial = 9,
    IssuerInitial = 11,
    ObserverJob = 20,
    ObserverPipeCreate = 21,
    ObserverPipeDescriptor = 22,
    ObserverAwaitFrame = 23,
    ObserverConnect = 24,
    ObserverHeader = 25,
    ObserverConnector = 26,
    ObserverToken = 27,
    ObserverPeerSid = 28,
    ObserverBody = 29,
    ObserverFrame = 30,
    ObserverChild = 31,
    ObserverRevoke = 32,
    ObserverAwaitRelease = 33,
    ObserverIssuerExit = 34,
    ObserverCleanup = 35,
    ObserverTerminal = 36,
    ObserverResume = 37,
    ObserverChildExit = 38,
    ObserverSdkRead = 39,
    IssuerAwaitStart = 40,
    IssuerChild = 41,
    IssuerRecord = 42,
    IssuerPipeOpen = 43,
    IssuerPipeDescriptor = 44,
    IssuerPipeWrite = 45,
    IssuerAwaitRevoke = 46,
    IssuerRelease = 47,
    IssuerCleanup = 48,
    SdkConnect = 50,
    SdkChallenge = 51,
    SdkRequest = 52,
    SdkConnector = 53,
    SdkToken = 54,
    SdkFrame = 55,
    SdkFile = 56,
    SdkReply = 57,
}
impl ProofPhase {
    pub fn code(self) -> u32 {
        self as u32
    }
}

#[path = "windows_scm_job_fixture.rs"]
mod job_fixture;

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
    thread_creation: u64,
}
impl Handoff {
    fn encode(self) -> String {
        format!(
            "JDC2\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.issuer.pid,
            self.issuer.creation,
            self.child.pid,
            self.child.creation,
            self.thread,
            self.thread_creation
        )
    }
    fn parse(text: &str) -> Result<Self, IdentityDenied> {
        let fields: Vec<_> = text.lines().collect();
        let ["JDC2", issuer, issuer_creation, child, child_creation, thread, thread_creation] =
            fields.as_slice()
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
            thread_creation: thread_creation.parse().map_err(|_| IdentityDenied)?,
        };
        if result.issuer.pid == 0
            || result.child.pid == 0
            || result.thread == 0
            || result.issuer.pid == result.child.pid
            || result.issuer.creation == 0
            || result.child.creation < result.issuer.creation
            || result.thread_creation < result.child.creation
            || result.encode() != text
        {
            return Err(IdentityDenied);
        }
        Ok(result)
    }
}

fn fixture_path(mode: JobProofMode) -> Result<PathBuf, IdentityDenied> {
    let exe = std::env::current_exe().map_err(|_| IdentityDenied)?;
    Ok(exe
        .parent()
        .ok_or(IdentityDenied)?
        .join("handoff")
        .join(mode.record(
            "issued-process.txt",
            "resume-issued-process.txt",
            "sdk-read-issued-process.txt",
        )))
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

fn open_observer_thread_pin(
    handoff: Handoff,
    process: BorrowedHandle<'_>,
) -> Result<OwnedHandle, IdentityDenied> {
    let raw = unsafe {
        OpenThread(
            THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            handoff.thread,
        )
    };
    if raw.is_null() {
        return Err(IdentityDenied);
    }
    let pin = unsafe { OwnedHandle::from_raw_handle(raw) };
    handoff.thread_identity().verify(process, pin.as_handle())?;
    Ok(pin)
}

impl Handoff {
    fn thread_identity(self) -> ThreadIdentity {
        ThreadIdentity {
            pid: self.child.pid,
            tid: self.thread,
            creation: self.thread_creation,
        }
    }
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
    denied_thread_control_rights(tid, JobProofMode::Observe)
}
fn denied_thread_control_rights(tid: u32, mode: JobProofMode) -> Result<(), IdentityDenied> {
    for access in [
        THREAD_GET_CONTEXT,
        THREAD_SET_CONTEXT,
        THREAD_SUSPEND_RESUME,
        THREAD_TERMINATE,
        THREAD_QUERY_INFORMATION,
        THREAD_SET_INFORMATION,
        THREAD_SET_LIMITED_INFORMATION,
        THREAD_SET_THREAD_TOKEN,
        THREAD_IMPERSONATE,
        THREAD_DIRECT_IMPERSONATION,
        0x0004_0000,
        0x0008_0000,
    ] {
        if mode.allows_resume() && access == THREAD_SUSPEND_RESUME {
            continue;
        }
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

pub fn issue(
    handler: &ServiceStatusHandle,
    stop: Receiver<()>,
    phase: &Cell<ProofPhase>,
    mode: JobProofMode,
) -> Result<(), IdentityDenied> {
    verify_scm_fixture_identity(ScmFixtureRole::Issuer).map_err(|_| IdentityDenied)?;
    seal_current_scm_fixture_issuer()?;
    let path = fixture_path(mode)?;
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
        thread_creation: child.primary_thread_identity()?.creation,
    };
    let job_proof = job_fixture::IssuerJobProof::prepare(mode)?;
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
    job_proof.run(handoff.issuer, phase, mode)?;
    phase.set(ProofPhase::IssuerCleanup);
    // A successful handoff requires issuer process exit, not a later
    // external stop request. Any premature STOP is a failed proof.
    if !matches!(stop.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)) {
        return Err(IdentityDenied);
    }
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

pub fn observe(phase: &Cell<ProofPhase>, mode: JobProofMode) -> Result<(), IdentityDenied> {
    verify_scm_fixture_identity(ScmFixtureRole::Authority).map_err(|_| IdentityDenied)?;
    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .map_err(|_| IdentityDenied)?;
    let service = manager
        .open_service(
            ScmFixtureRole::Issuer.service_name(),
            ServiceAccess::QUERY_STATUS,
        )
        .map_err(|_| IdentityDenied)?;
    let record = fixture_path(mode)?;
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
    // The original child has no thread-observation grant. The job child
    // alone receives the deliberately limited read-only authority pin.
    let raw = unsafe {
        OpenThread(
            THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            handoff.thread,
        )
    };
    let error = unsafe { GetLastError() };
    if !raw.is_null() {
        unsafe { CloseHandle(raw) };
        return Err(IdentityDenied);
    }
    if error != ERROR_ACCESS_DENIED {
        return Err(IdentityDenied);
    }
    handoff.issuer.verify(issuer.as_handle())?;
    handoff.child.verify(child.as_handle())?;
    job_fixture::observe(
        handoff.issuer,
        handoff.child,
        &issuer,
        &child,
        phase,
        mode,
        &service,
    )?;
    phase.set(ProofPhase::ObserverTerminal);
    verify_terminal_issuer(&service, mode)
}

fn verify_terminal_issuer(service: &Service, mode: JobProofMode) -> Result<(), IdentityDenied> {
    let status = service.query_status().map_err(|_| IdentityDenied)?;
    if status.current_state != ServiceState::Stopped
        || status.process_id.is_some()
        || status.exit_code != ServiceExitCode::ServiceSpecific(mode.issuer_success())
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn thread_creation_is_mandatory_in_canonical_handoff() {
        let valid = "JDC2\n10\n100\n20\n101\n30\n102\n";
        let parsed = Handoff::parse(valid).unwrap();
        assert_eq!(parsed.thread_creation, 102);
        assert_eq!(parsed.encode(), valid);
        for bad in [
            "JDC1\n10\n100\n20\n101\n30\n",
            "JDC2\n10\n100\n20\n101\n30\n99\n",
            "JDC2\n10\n100\n20\n101\n30\n0\n",
            "JDC2\n10\n100\n20\n101\n30\n0102\n",
        ] {
            assert!(Handoff::parse(bad).is_err());
        }
    }

    #[test]
    fn handoff_rejects_ambiguous_or_invalid_locators() {
        let valid = "JDC2\n10\n100\n20\n101\n30\n102\n";
        assert_eq!(Handoff::parse(valid).unwrap().encode(), valid);
        for bad in [
            "JDC2\n10\n100\n10\n101\n30\n102\n",
            "JDC2\n10\n100\n20\n99\n30\n102\n",
            "JDC2\n0\n100\n20\n101\n30\n102\n",
            "JDC2\n10\n100\n20\n101\n0\n102\n",
            "JDC2\n010\n100\n20\n101\n30\n102\n",
            "JDC2\n10\n100\n20\n101\n30\n102\nextra\n",
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
