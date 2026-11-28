//! Disposable SCM job-owner/issuer experiment, never production IPC.
//! The two fixed virtual accounts participate only in the hosted proof.
use super::{
    denied_process_rights, denied_thread_control_rights, open_observer_pin,
    open_observer_thread_pin, verify_terminal_issuer, Handoff, JobProofMode, ProofPhase, Stamp,
};
use jdc_authority_service::{
    windows_issued_client::IssuedClient,
    windows_token::{
        scm_fixture_sid, verify_scm_fixture_identity, verify_scm_fixture_process_identity,
        ScmFixtureRole,
    },
    IdentityDenied,
};
use std::cell::Cell;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    mem::size_of,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    path::PathBuf,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        GetHandleInformation, GetLastError, LocalFree, SetLastError, ERROR_ACCESS_DENIED,
        ERROR_ALREADY_EXISTS, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_KERNEL_OBJECT,
        },
        GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, IsValidAcl,
        SetKernelObjectSecurity, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
    },
    Storage::FileSystem::{STANDARD_RIGHTS_REQUIRED, SYNCHRONIZE},
    System::{
        JobObjects::*,
        SystemServices::{
            JOB_OBJECT_ASSIGN_PROCESS, JOB_OBJECT_IMPERSONATE, JOB_OBJECT_QUERY,
            JOB_OBJECT_SET_ATTRIBUTES, JOB_OBJECT_SET_SECURITY_ATTRIBUTES, JOB_OBJECT_TERMINATE,
        },
        Threading::{
            CreateEventW, GetCurrentProcess, GetExitCodeProcess, GetProcessMitigationPolicy,
            OpenEventW, ProcessChildProcessPolicy, SetEvent, WaitForSingleObject, EVENT_ALL_ACCESS,
            EVENT_MODIFY_STATE,
        },
    },
};
#[path = "windows_scm_handoff_pipe.rs"]
mod handoff_pipe;

const LIMITS: u32 = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
const WAIT_MS: u32 = 5000;
// WinNT JOB_OBJECT_ALL_ACCESS: standard rights, synchronization and all six job-specific rights.
const JOB_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3f;
fn fixture_prefix(stage: &str) -> Result<String, IdentityDenied> {
    let id = stage.strip_prefix("JDC-T011-SCM-").ok_or(IdentityDenied)?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(IdentityDenied);
    }
    Ok(format!("Local\\JdcT011Job-{id}"))
}
struct Names {
    prefix: String,
    record: PathBuf,
    mode: JobProofMode,
}
impl Names {
    fn for_role(role: ScmFixtureRole, mode: JobProofMode) -> Result<Self, IdentityDenied> {
        verify_scm_fixture_identity(role).map_err(|_| IdentityDenied)?;
        let exe = std::env::current_exe().map_err(|_| IdentityDenied)?;
        if exe.file_name().and_then(|v| v.to_str()) != Some("jdc-authority-scm-issued-proof.exe") {
            return Err(IdentityDenied);
        }
        let stage = exe.parent().ok_or(IdentityDenied)?;
        let prefix = fixture_prefix(
            stage
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or(IdentityDenied)?,
        )?;
        Ok(Self {
            prefix,
            record: stage
                .join("handoff")
                .join(mode.record("job-issued-process.txt", "resume-job-issued-process.txt")),
            mode,
        })
    }
    fn object(&self, suffix: &str) -> Vec<u16> {
        format!("{}{}-{suffix}", self.prefix, self.mode.suffix())
            .encode_utf16()
            .chain(Some(0))
            .collect()
    }
}
struct Local(*mut std::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}
fn sid_string(sid: *mut std::ffi::c_void) -> Result<String, IdentityDenied> {
    if sid.is_null() {
        return Err(IdentityDenied);
    }
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err(IdentityDenied);
    }
    let _owner = Local(text.cast());
    let len = (0..192)
        .find(|&i| unsafe { *text.add(i) } == 0)
        .ok_or(IdentityDenied)?;
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) }).map_err(|_| IdentityDenied)
}
fn role_sid(role: ScmFixtureRole) -> Result<String, IdentityDenied> {
    let sid = scm_fixture_sid(role).map_err(|_| IdentityDenied)?;
    let mut aligned = vec![0usize; sid.len().div_ceil(size_of::<usize>())];
    unsafe { ptr::copy_nonoverlapping(sid.as_ptr(), aligned.as_mut_ptr().cast::<u8>(), sid.len()) };
    sid_string(aligned.as_mut_ptr().cast())
}
fn descriptor(
    owner: ScmFixtureRole,
    peer: Option<(ScmFixtureRole, u32)>,
    full_access: u32,
) -> Result<Local, IdentityDenied> {
    let owner = role_sid(owner)?;
    let peer = peer
        .map(|(role, rights)| role_sid(role).map(|sid| (sid, rights)))
        .transpose()?;
    descriptor_for_sids(
        &owner,
        peer.as_ref().map(|(sid, rights)| (sid.as_str(), *rights)),
        full_access,
    )
}
fn descriptor_for_sids(
    owner: &str,
    peer: Option<(&str, u32)>,
    full_access: u32,
) -> Result<Local, IdentityDenied> {
    let peer = if let Some((sid, rights)) = peer {
        if sid == owner {
            return Err(IdentityDenied);
        }
        format!("(A;;0x{rights:x};;;{sid})")
    } else {
        String::new()
    };
    let sddl =
        format!("D:P(A;;0x{full_access:x};;;SY)(A;;0x{full_access:x};;;{owner})(A;;RC;;;OW){peer}");
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut raw = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            1,
            &mut raw,
            ptr::null_mut(),
        )
    } == 0
        || raw.is_null()
    {
        return Err(IdentityDenied);
    }
    Ok(Local(raw))
}
fn attributes(sd: &Local) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    }
}
fn owned(raw: HANDLE) -> Result<OwnedHandle, IdentityDenied> {
    if raw.is_null() {
        return Err(IdentityDenied);
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut flags = 0;
    if unsafe { GetHandleInformation(raw, &mut flags) } == 0 || flags & HANDLE_FLAG_INHERIT != 0 {
        return Err(IdentityDenied);
    }
    Ok(handle)
}
fn created(raw: HANDLE, error: u32) -> Result<OwnedHandle, IdentityDenied> {
    let handle = owned(raw)?;
    if error == ERROR_ALREADY_EXISTS {
        return Err(IdentityDenied);
    }
    Ok(handle)
}
fn new_event(
    names: &Names,
    suffix: &str,
    owner: ScmFixtureRole,
    peer: ScmFixtureRole,
    rights: u32,
) -> Result<OwnedHandle, IdentityDenied> {
    let sd = descriptor(owner, Some((peer, rights)), EVENT_ALL_ACCESS)?;
    let sa = attributes(&sd);
    let name = names.object(suffix);
    unsafe { SetLastError(0) };
    let raw = unsafe { CreateEventW(&sa, 0, 0, name.as_ptr()) };
    let error = unsafe { GetLastError() };
    let event = created(raw, error)?;
    verify_security(event.as_handle(), &role_sid(owner)?, &sd)?;
    Ok(event)
}
fn open_event(names: &Names, suffix: &str, access: u32) -> Result<OwnedHandle, IdentityDenied> {
    owned(unsafe { OpenEventW(access, 0, names.object(suffix).as_ptr()) })
}
fn signal(handle: &OwnedHandle) -> Result<(), IdentityDenied> {
    if unsafe { SetEvent(handle.as_raw_handle()) } == 0 {
        return Err(IdentityDenied);
    }
    Ok(())
}
fn wait(handle: &OwnedHandle, timeout: u32) -> Result<(), IdentityDenied> {
    if unsafe { WaitForSingleObject(handle.as_raw_handle(), timeout) } != WAIT_OBJECT_0 {
        return Err(IdentityDenied);
    }
    Ok(())
}
fn denied_job_open(names: &Names, access: u32) -> Result<(), IdentityDenied> {
    let raw = unsafe { OpenJobObjectW(access, 0, names.object("job").as_ptr()) };
    let error = unsafe { GetLastError() };
    if !raw.is_null() {
        drop(unsafe { OwnedHandle::from_raw_handle(raw) });
        return Err(IdentityDenied);
    }
    if error != ERROR_ACCESS_DENIED {
        return Err(IdentityDenied);
    }
    Ok(())
}
fn forbidden_job_rights(names: &Names) -> Result<(), IdentityDenied> {
    for access in [
        JOB_OBJECT_QUERY,
        JOB_OBJECT_SET_ATTRIBUTES,
        JOB_OBJECT_TERMINATE,
        JOB_OBJECT_SET_SECURITY_ATTRIBUTES,
        JOB_OBJECT_IMPERSONATE,
        0x0002_0000,
        0x0004_0000,
        0x0008_0000,
        SYNCHRONIZE,
    ] {
        denied_job_open(names, access)?;
    }
    Ok(())
}
fn write_record(path: &std::path::Path, handoff: Handoff) -> Result<(), IdentityDenied> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| IdentityDenied)?;
    file.write_all(handoff.encode().as_bytes())
        .map_err(|_| IdentityDenied)?;
    file.sync_all().map_err(|_| IdentityDenied)
}
fn read_record(path: &std::path::Path) -> Result<Handoff, IdentityDenied> {
    match OpenOptions::new().write(true).open(path) {
        Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {}
        _ => return Err(IdentityDenied),
    }
    let mut text = String::new();
    File::open(path)
        .map_err(|_| IdentityDenied)?
        .take(129)
        .read_to_string(&mut text)
        .map_err(|_| IdentityDenied)?;
    if text.len() > 128 {
        return Err(IdentityDenied);
    }
    Handoff::parse(&text)
}
pub(super) struct IssuerJobProof {
    names: Names,
    start: OwnedHandle,
    ack: OwnedHandle,
}
impl IssuerJobProof {
    pub(super) fn prepare(mode: JobProofMode) -> Result<Self, IdentityDenied> {
        let names = Names::for_role(ScmFixtureRole::Issuer, mode)?;
        let start = new_event(
            &names,
            "start",
            ScmFixtureRole::Issuer,
            ScmFixtureRole::Authority,
            EVENT_MODIFY_STATE,
        )?;
        let ack = new_event(
            &names,
            "ack",
            ScmFixtureRole::Issuer,
            ScmFixtureRole::Authority,
            SYNCHRONIZE,
        )?;
        Ok(Self { names, start, ack })
    }
    pub(super) fn run(
        &self,
        issuer: Stamp,
        phase: &Cell<ProofPhase>,
        mode: JobProofMode,
    ) -> Result<(), IdentityDenied> {
        phase.set(ProofPhase::IssuerAwaitStart);
        wait(&self.start, 15000)?;
        phase.set(ProofPhase::IssuerChild);
        let revoked = open_event(&self.names, "revoked", SYNCHRONIZE)?;
        let assignment = owned(unsafe {
            OpenJobObjectW(
                JOB_OBJECT_ASSIGN_PROCESS,
                0,
                self.names.object("job").as_ptr(),
            )
        })?;
        forbidden_job_rights(&self.names)?;
        let child = if mode == JobProofMode::Resume {
            IssuedClient::launch_scm_resume_fixture(assignment)?
        } else {
            IssuedClient::launch_scm_job_fixture(assignment)?
        };
        verify_scm_fixture_process_identity(ScmFixtureRole::Issuer, child.process_handle())
            .map_err(|_| IdentityDenied)?;
        if verify_scm_fixture_process_identity(ScmFixtureRole::Authority, child.process_handle())
            .is_ok()
        {
            return Err(IdentityDenied);
        }
        let mut policy = 0u32;
        if unsafe {
            GetProcessMitigationPolicy(
                child.process_handle().as_raw_handle(),
                ProcessChildProcessPolicy,
                (&mut policy as *mut u32).cast(),
                size_of::<u32>(),
            )
        } == 0
            || policy & 1 != 1
        {
            return Err(IdentityDenied);
        }
        issuer.verify(unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) })?;
        let handoff = Handoff {
            issuer,
            child: Stamp::capture(child.process_handle())?,
            thread: child.tid(),
            thread_creation: child.primary_thread_identity()?.creation,
        };
        phase.set(ProofPhase::IssuerRecord);
        write_record(&self.names.record, handoff)?;
        let channel = handoff_pipe::send(&self.names, handoff, phase)?;
        phase.set(ProofPhase::IssuerAwaitRevoke);
        signal(&self.ack)?;
        wait(&revoked, WAIT_MS)?;
        // A DACL update cannot revoke an already-open handle. Relinquish
        // the assignment and creation handles together. Only the authority's
        // job keeps the never-resumed fixture alive after issuer exit.
        phase.set(ProofPhase::IssuerRelease);
        denied_job_open(&self.names, JOB_OBJECT_ASSIGN_PROCESS)?;
        forbidden_job_rights(&self.names)?;
        drop(channel);
        child.relinquish()?;
        signal(&self.ack)
    }
}
fn dacl(sd: &Local) -> Result<*mut ACL, IdentityDenied> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut acl, &mut defaulted) } == 0
        || present == 0
        || defaulted != 0
        || acl.is_null()
    {
        return Err(IdentityDenied);
    }
    Ok(acl)
}
fn acl_aces(acl: *mut ACL) -> Result<Vec<Vec<u8>>, IdentityDenied> {
    if acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
        return Err(IdentityDenied);
    }
    let length = unsafe { (*acl).AclSize } as usize;
    let count = unsafe { (*acl).AceCount };
    if !(size_of::<ACL>()..=4096).contains(&length) || !(1..=4).contains(&count) {
        return Err(IdentityDenied);
    }
    let mut aces = Vec::with_capacity(count as usize);
    for index in 0..count {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(acl, u32::from(index), &mut raw) } == 0 || raw.is_null() {
            return Err(IdentityDenied);
        }
        let offset = (raw as usize)
            .checked_sub(acl as usize)
            .ok_or(IdentityDenied)?;
        if offset < size_of::<ACL>()
            || offset
                .checked_add(size_of::<ACE_HEADER>())
                .filter(|end| *end <= length)
                .is_none()
        {
            return Err(IdentityDenied);
        }
        let size = unsafe { (*raw.cast::<ACE_HEADER>()).AceSize } as usize;
        if size < size_of::<ACE_HEADER>()
            || offset
                .checked_add(size)
                .filter(|end| *end <= length)
                .is_none()
        {
            return Err(IdentityDenied);
        }
        aces.push(unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), size) }.to_vec());
    }
    Ok(aces)
}
fn object_security(
    handle: BorrowedHandle<'_>,
) -> Result<(String, Vec<Vec<u8>>, bool), IdentityDenied> {
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut raw = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut raw,
        )
    };
    let sd = Local(raw);
    if status != 0 || raw.is_null() || owner.is_null() || acl.is_null() {
        return Err(IdentityDenied);
    }
    let (mut control, mut revision) = (0u16, 0u32);
    if unsafe { GetSecurityDescriptorControl(sd.0, &mut control, &mut revision) } == 0 {
        return Err(IdentityDenied);
    }
    Ok((
        sid_string(owner)?,
        acl_aces(acl)?,
        control & SE_DACL_PROTECTED != 0,
    ))
}
fn verify_security(
    handle: BorrowedHandle<'_>,
    owner: &str,
    expected: &Local,
) -> Result<(), IdentityDenied> {
    let (actual_owner, actual_aces, protected) = object_security(handle)?;
    if !protected || actual_owner != owner || actual_aces != acl_aces(dacl(expected)?)? {
        return Err(IdentityDenied);
    }
    Ok(())
}
struct AuthorityJob(OwnedHandle);
impl AuthorityJob {
    fn new(names: &Names) -> Result<Self, IdentityDenied> {
        let sd = descriptor(
            ScmFixtureRole::Authority,
            Some((ScmFixtureRole::Issuer, JOB_OBJECT_ASSIGN_PROCESS)),
            JOB_ALL_ACCESS,
        )?;
        let sa = attributes(&sd);
        unsafe { SetLastError(0) };
        let raw = unsafe { CreateJobObjectW(&sa, names.object("job").as_ptr()) };
        let error = unsafe { GetLastError() };
        let job = Self(created(raw, error)?);
        job.verify_dacl(&sd)?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = LIMITS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        if unsafe {
            SetInformationJobObject(
                job.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(IdentityDenied);
        }
        job.verify_limits()?;
        job.counts(0, 0)?;
        Ok(job)
    }
    fn verify_dacl(&self, expected: &Local) -> Result<(), IdentityDenied> {
        verify_security(
            self.0.as_handle(),
            &role_sid(ScmFixtureRole::Authority)?,
            expected,
        )
    }
    fn revoke(&self) -> Result<(), IdentityDenied> {
        let sd = descriptor(ScmFixtureRole::Authority, None, JOB_ALL_ACCESS)?;
        if unsafe {
            SetKernelObjectSecurity(self.0.as_raw_handle(), DACL_SECURITY_INFORMATION, sd.0)
        } == 0
        {
            return Err(IdentityDenied);
        }
        self.verify_dacl(&sd)?;
        self.verify_limits()
    }
    fn verify_limits(&self) -> Result<(), IdentityDenied> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut used = 0;
        if unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut used,
            )
        } == 0
            || used != size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32
            || limits.BasicLimitInformation.LimitFlags != LIMITS
            || limits.BasicLimitInformation.ActiveProcessLimit != 1
        {
            return Err(IdentityDenied);
        }
        Ok(())
    }
    fn counts(&self, total: u32, active: u32) -> Result<(), IdentityDenied> {
        let mut counts = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut used = 0;
        if unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&mut counts as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                &mut used,
            )
        } == 0
            || used != size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32
            || counts.TotalProcesses != total
            || counts.ActiveProcesses != active
        {
            return Err(IdentityDenied);
        }
        Ok(())
    }
    fn verify_child(&self, child: BorrowedHandle<'_>) -> Result<(), IdentityDenied> {
        self.verify_limits()?;
        let mut member = 0;
        if unsafe { IsProcessInJob(child.as_raw_handle(), self.0.as_raw_handle(), &mut member) }
            == 0
            || member == 0
        {
            return Err(IdentityDenied);
        }
        self.counts(1, 1)
    }
}
pub(super) fn observe(
    issuer: Stamp,
    original_child: Stamp,
    issuer_pin: &OwnedHandle,
    original_pin: &OwnedHandle,
    phase: &Cell<ProofPhase>,
    mode: JobProofMode,
    service: &windows_service::service::Service,
) -> Result<(), IdentityDenied> {
    phase.set(ProofPhase::ObserverJob);
    let names = Names::for_role(ScmFixtureRole::Authority, mode)?;
    let start = open_event(&names, "start", EVENT_MODIFY_STATE)?;
    let ack = open_event(&names, "ack", SYNCHRONIZE)?;
    let revoked = new_event(
        &names,
        "revoked",
        ScmFixtureRole::Authority,
        ScmFixtureRole::Issuer,
        SYNCHRONIZE,
    )?;
    let job = AuthorityJob::new(&names)?;
    let channel = handoff_pipe::HandoffPipe::create(&names, phase)?;
    phase.set(ProofPhase::ObserverAwaitFrame);
    signal(&start)?;
    wait(&ack, WAIT_MS)?;
    let expected_sid = scm_fixture_sid(ScmFixtureRole::Issuer).map_err(|_| IdentityDenied)?;
    let handoff = channel.receive_traced(issuer_pin.as_handle(), &expected_sid, phase)?;
    phase.set(ProofPhase::ObserverChild);
    // The record is retained only for independent hosted custody evidence.
    // It cannot authorize a handoff without the live authenticated channel.
    if handoff.encode() != read_record(&names.record)?.encode()
        || handoff.issuer != issuer
        || handoff.child == original_child
    {
        return Err(IdentityDenied);
    }
    let child = open_observer_pin(handoff.child)?;
    let thread = open_observer_thread_pin(handoff, child.as_handle())?;
    // Reject the same live TID with stale creation identity, even though
    // the exact original read-only thread handle remains pinned.
    if open_observer_thread_pin(
        Handoff {
            thread_creation: handoff.thread_creation ^ 1,
            ..handoff
        },
        child.as_handle(),
    )
    .is_ok()
    {
        return Err(IdentityDenied);
    }
    denied_process_rights(handoff.child.pid)?;
    denied_thread_control_rights(handoff.thread, mode)?;
    job.verify_child(child.as_handle())?;
    handoff.child.verify(child.as_handle())?;
    handoff
        .thread_identity()
        .verify(child.as_handle(), thread.as_handle())?;
    // A still-live issuer must never satisfy the resume gate.
    if require_clean_issuer_exit(issuer_pin.as_handle()).is_ok() {
        return Err(IdentityDenied);
    }
    phase.set(ProofPhase::ObserverRevoke);
    job.revoke()?;
    signal(&revoked)?;
    phase.set(ProofPhase::ObserverAwaitRelease);
    wait(&ack, WAIT_MS)?;
    phase.set(ProofPhase::ObserverIssuerExit);
    // An acknowledgment alone is insufficient. The live child must survive
    // the actual issuer process exit, while the authority retains the job.
    handoff.child.verify(child.as_handle())?;
    wait(original_pin, WAIT_MS)?;
    let mut exit = u32::MAX;
    if unsafe { GetExitCodeProcess(original_pin.as_raw_handle(), &mut exit) } == 0 || exit != 1 {
        return Err(IdentityDenied);
    }
    wait(issuer_pin, WAIT_MS)?;
    require_clean_issuer_exit(issuer_pin.as_handle())?;
    verify_terminal_issuer(service, mode)?;
    handoff.child.verify(child.as_handle())?;
    handoff
        .thread_identity()
        .verify(child.as_handle(), thread.as_handle())?;
    job.verify_child(child.as_handle())?;
    if mode == JobProofMode::Resume {
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
        };
        phase.set(ProofPhase::ObserverResume);
        require_clean_issuer_exit(issuer_pin.as_handle())?;
        let resume = owned(unsafe {
            OpenThread(
                THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | SYNCHRONIZE,
                0,
                handoff.thread,
            )
        })?;
        handoff
            .thread_identity()
            .verify(child.as_handle(), resume.as_handle())?;
        if unsafe { ResumeThread(resume.as_raw_handle()) } != 1 {
            return Err(IdentityDenied);
        }
        drop(resume);
        phase.set(ProofPhase::ObserverChildExit);
        wait(&child, WAIT_MS)?;
        wait(&thread, WAIT_MS)?;
        let mut exit = u32::MAX;
        if unsafe { GetExitCodeProcess(child.as_raw_handle(), &mut exit) } == 0 || exit != 17 {
            return Err(IdentityDenied);
        }
    }
    phase.set(ProofPhase::ObserverCleanup);
    drop(job);
    // The observer-only child never ran; last job close must signal both.
    // In the resume scenario both must already have exited with the fixed code.
    wait(&child, WAIT_MS)?;
    wait(&thread, WAIT_MS)?;
    if handoff
        .thread_identity()
        .verify(child.as_handle(), thread.as_handle())
        .is_ok()
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

fn require_clean_issuer_exit(issuer: BorrowedHandle<'_>) -> Result<(), IdentityDenied> {
    let mut code = u32::MAX;
    if unsafe { WaitForSingleObject(issuer.as_raw_handle(), 0) } != WAIT_OBJECT_0
        || unsafe { GetExitCodeProcess(issuer.as_raw_handle(), &mut code) } == 0
        || code != 0
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resume_gate_requires_a_real_cleanly_exited_issuer() {
        use std::process::Command;
        let raw = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION
                    | SYNCHRONIZE,
                0,
                std::process::id(),
            )
        };
        let current = owned(raw).unwrap();
        assert!(require_clean_issuer_exit(current.as_handle()).is_err());
        let image = std::env::current_exe().unwrap();
        let mut child = Command::new(&image)
            .args([
                "--exact",
                "observation::job_fixture::tests::job_names_are_bound_to_the_unique_fixture_stage",
            ])
            .spawn()
            .unwrap();
        assert!(child.wait().unwrap().success());
        use std::os::windows::io::AsHandle;
        assert!(require_clean_issuer_exit(child.as_handle()).is_ok());
        let mut failed = Command::new(&image)
            .arg("--not-a-valid-test-argument")
            .spawn()
            .unwrap();
        assert!(!failed.wait().unwrap().success());
        assert!(require_clean_issuer_exit(failed.as_handle()).is_err());
    }
    #[test]
    fn job_names_are_bound_to_the_unique_fixture_stage() {
        let stage = "JDC-T011-SCM-0123456789abcdef0123456789abcdef";
        assert_eq!(
            fixture_prefix(stage).unwrap(),
            "Local\\JdcT011Job-0123456789abcdef0123456789abcdef"
        );
        for bad in [
            "",
            "JDC-T011-SCM-abc",
            "JDC-T011-SCM-0123456789abcdef0123456789abcdeg",
            "JDC-T011-SCM-0123456789ABCDEF0123456789ABCDEF",
            "../JDC-T011-SCM-0123456789abcdef0123456789abcdef",
        ] {
            assert!(fixture_prefix(bad).is_err());
        }
    }
    #[test]
    fn local_unnamed_job_descriptor_update_preserves_owner_and_exact_acl() {
        // No real peer or named namespace is exposed by this local control.
        use windows_sys::Win32::Security::GetSecurityDescriptorOwner;
        let probe = owned(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) }).unwrap();
        let mut raw = ptr::null_mut();
        let mut owner = ptr::null_mut();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    probe.as_raw_handle(),
                    SE_KERNEL_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    &mut owner,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut raw,
                )
            },
            0
        );
        let owner_sd = Local(raw);
        let mut defaulted = 0;
        assert_ne!(
            unsafe { GetSecurityDescriptorOwner(owner_sd.0, &mut owner, &mut defaulted) },
            0
        );
        let owner = sid_string(owner).unwrap();
        let event_sd =
            descriptor_for_sids(&owner, Some(("S-1-0-0", SYNCHRONIZE)), EVENT_ALL_ACCESS).unwrap();
        let event_sa = attributes(&event_sd);
        let event = owned(unsafe { CreateEventW(&event_sa, 0, 0, ptr::null()) }).unwrap();
        verify_security(event.as_handle(), &owner, &event_sd).unwrap();
        let initial = descriptor_for_sids(
            &owner,
            Some(("S-1-0-0", JOB_OBJECT_ASSIGN_PROCESS)),
            JOB_ALL_ACCESS,
        )
        .unwrap();
        let sa = attributes(&initial);
        let job = owned(unsafe { CreateJobObjectW(&sa, ptr::null()) }).unwrap();
        verify_security(job.as_handle(), &owner, &initial).unwrap();
        let final_sd = descriptor_for_sids(&owner, None, JOB_ALL_ACCESS).unwrap();
        assert_ne!(
            unsafe {
                SetKernelObjectSecurity(job.as_raw_handle(), DACL_SECURITY_INFORMATION, final_sd.0)
            },
            0,
            "Win32 error {}",
            unsafe { GetLastError() }
        );
        verify_security(job.as_handle(), &owner, &final_sd).unwrap();
        assert!(verify_security(job.as_handle(), &owner, &initial).is_err());
    }
    #[test]
    fn ordinary_process_cannot_enter_fixture_roles() {
        for mode in [JobProofMode::Observe, JobProofMode::Resume] {
            assert!(Names::for_role(ScmFixtureRole::Issuer, mode).is_err());
            assert!(Names::for_role(ScmFixtureRole::Authority, mode).is_err());
        }
    }
}
