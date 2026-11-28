//! Owns a child created with kernel-enforced process and thread DACLs.
//! This is a process-lifetime primitive, NOT an authorized managed launcher:
//! its caller must already have authenticated SCM identity, protected image
//! custody, installed policy, and an independently approved request source.
//! No client-supplied binary, command, environment or token is accepted via IPC.
use crate::{
    policy_epoch::{PolicyFence, ReadTicket},
    windows_creation_custody::OwnerRightsCreationDescriptors,
    windows_opened_read::read_opened_regular,
    windows_pipe_disclosure::disclose_bounded,
    windows_pipe_peer::{
        observe_client_sid_after_read, observe_process_sid, verify_live_issued_peer_after_read,
    },
    IdentityDenied,
};
use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::File,
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, WAIT_OBJECT_0},
    Security::TOKEN_QUERY,
    System::Threading::{
        CreateProcessW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, ResumeThread,
        TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
        CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
    },
};

fn wide(value: &OsStr) -> Result<Vec<u16>, IdentityDenied> {
    let encoded: Vec<u16> = value.encode_wide().collect();
    if encoded.is_empty() || encoded.len() >= 32_767 || encoded.contains(&0) {
        return Err(IdentityDenied);
    }
    Ok(encoded.into_iter().chain(std::iter::once(0)).collect())
}

fn environment_block(pairs: &[(&str, &str)]) -> Result<Vec<u16>, IdentityDenied> {
    if pairs.is_empty() || pairs.len() > 32 {
        return Err(IdentityDenied);
    }
    let mut seen = HashSet::new();
    let mut entries = Vec::with_capacity(pairs.len());
    for &(name, value) in pairs {
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || value.contains('\0')
            || !seen.insert(name.to_ascii_lowercase())
        {
            return Err(IdentityDenied);
        }
        entries.push((name.to_ascii_lowercase(), format!("{name}={value}")));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut block = Vec::new();
    for (_, entry) in entries {
        block.extend(entry.encode_utf16());
        block.push(0);
    }
    block.push(0);
    if block.len() > 32_767 {
        return Err(IdentityDenied);
    }
    Ok(block)
}

/// Read-only kernel observation; a matching stamp is not an authorization or
/// permission to resume a thread. The caller must retain both real handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadIdentity {
    pub pid: u32,
    pub tid: u32,
    pub creation: u64,
}
impl ThreadIdentity {
    pub fn capture(
        process: BorrowedHandle<'_>,
        thread: BorrowedHandle<'_>,
    ) -> Result<Self, IdentityDenied> {
        use windows_sys::Win32::{
            Foundation::{FILETIME, INVALID_HANDLE_VALUE, WAIT_TIMEOUT},
            System::Threading::{GetProcessId, GetProcessIdOfThread, GetThreadId, GetThreadTimes},
        };
        let process = process.as_raw_handle();
        let thread = thread.as_raw_handle();
        if [process, thread]
            .iter()
            .any(|&h| h.is_null() || h == INVALID_HANDLE_VALUE)
        {
            return Err(IdentityDenied);
        }
        let live = || unsafe {
            WaitForSingleObject(process, 0) == WAIT_TIMEOUT
                && WaitForSingleObject(thread, 0) == WAIT_TIMEOUT
        };
        if !live() {
            return Err(IdentityDenied);
        }
        let pid = unsafe { GetProcessId(process) };
        let tid = unsafe { GetThreadId(thread) };
        let (mut creation, mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        if pid == 0
            || tid == 0
            || unsafe { GetProcessIdOfThread(thread) } != pid
            || unsafe { GetThreadTimes(thread, &mut creation, &mut exit, &mut kernel, &mut user) }
                == 0
        {
            return Err(IdentityDenied);
        }
        let creation =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if creation == 0 || !live() {
            return Err(IdentityDenied);
        }
        Ok(Self { pid, tid, creation })
    }
    pub fn verify(
        self,
        process: BorrowedHandle<'_>,
        thread: BorrowedHandle<'_>,
    ) -> Result<(), IdentityDenied> {
        if Self::capture(process, thread)? != self {
            return Err(IdentityDenied);
        }
        Ok(())
    }
}

/// The issuer alone retains both creation-time OS object handles. There is
/// deliberately no public constructor from a numeric PID or an arbitrary HANDLE.
pub struct IssuedClient {
    process: OwnedHandle,
    primary_thread: OwnedHandle,
    pid: u32,
    tid: u32,
    resumed: bool,
    terminate_on_drop: bool,
}

/// The fixed, never-resumed SCM fixture child holds only its own creation
/// handles and the issuer's temporary assignment handle. Ordinary process
/// launchers cannot construct this type or relinquish their cleanup duty.
pub struct ScmJobFixtureChild {
    child: IssuedClient,
    assignment: OwnedHandle,
}
impl ScmJobFixtureChild {
    pub fn process_handle(&self) -> BorrowedHandle<'_> {
        self.child.process_handle()
    }
    pub fn tid(&self) -> u32 {
        self.child.tid()
    }
    pub fn primary_thread_identity(&self) -> Result<ThreadIdentity, IdentityDenied> {
        self.child.primary_thread_identity()
    }
    /// Only called after the separately verified job owner acknowledges
    /// membership and revokes new assignments. Job close is the fail-safe.
    /// This fixture never grants a resume right or arbitrary launch authority.
    pub fn relinquish(self) -> Result<(), IdentityDenied> {
        crate::windows_token::verify_scm_fixture_identity(
            crate::windows_token::ScmFixtureRole::Issuer,
        )
        .map_err(|_| IdentityDenied)?;
        self.finish_verified_handoff()
    }

    fn finish_verified_handoff(mut self) -> Result<(), IdentityDenied> {
        if self.child.resumed
            || unsafe { WaitForSingleObject(self.child.process_handle().as_raw_handle(), 0) }
                != windows_sys::Win32::Foundation::WAIT_TIMEOUT
        {
            return Err(IdentityDenied);
        }
        let mut flags = 0;
        if unsafe {
            windows_sys::Win32::Foundation::GetHandleInformation(
                self.assignment.as_raw_handle(),
                &mut flags,
            )
        } == 0
            || flags & windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT != 0
        {
            return Err(IdentityDenied);
        }
        self.child.terminate_on_drop = false;
        // Drop closes the original process/thread and assignment handles.
        Ok(())
    }
}

impl IssuedClient {
    /// Create a suspended child using the *current process* primary token;
    /// matching these DACLs to a separately supplied/forged token is forbidden.
    /// Callers MUST verify SCM service identity and pin the installed image
    /// in an administrator-protected directory before invoking this method.
    pub fn launch_suspended(
        executable: &Path,
        command_line: &OsStr,
        environment: &[(&str, &str)],
    ) -> Result<Self, IdentityDenied> {
        Self::launch_suspended_with_observation(executable, command_line, environment, false, None)
    }

    /// Only the fixed SCM issuer role may create an observable proof child.
    /// This does not grant the observer a launch, thread or file capability.
    pub fn launch_scm_observable_fixture(
        executable: &Path,
        command_line: &OsStr,
        environment: &[(&str, &str)],
    ) -> Result<Self, IdentityDenied> {
        Self::launch_suspended_with_observation(executable, command_line, environment, true, None)
    }

    /// Disposable SCM proof only: the verified fixed issuer may associate its
    /// suspended fixture image with an already-open assignment-only job.
    /// No inherited handles, resume or service authority are granted here.
    pub fn launch_scm_job_fixture(job: OwnedHandle) -> Result<ScmJobFixtureChild, IdentityDenied> {
        crate::windows_token::verify_scm_fixture_identity(
            crate::windows_token::ScmFixtureRole::Issuer,
        )
        .map_err(|_| IdentityDenied)?;
        let image = std::env::current_exe().map_err(|_| IdentityDenied)?;
        if image.file_name().and_then(|v| v.to_str()) != Some("jdc-authority-scm-issued-proof.exe")
        {
            return Err(IdentityDenied);
        }
        let stage = image.parent().ok_or(IdentityDenied)?;
        let id = stage
            .file_name()
            .and_then(|v| v.to_str())
            .and_then(|v| v.strip_prefix("JDC-T011-SCM-"))
            .ok_or(IdentityDenied)?;
        if id.len() != 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(IdentityDenied);
        }
        let image = stage.join("jdc-authority-scm-issued-client.exe");
        let mut command = std::ffi::OsString::from("\"");
        command.push(image.as_os_str());
        command.push(OsStr::new("\""));
        let system = std::env::var("SystemRoot").map_err(|_| IdentityDenied)?;
        let child = Self::launch_suspended_with_observation(
            &image,
            &command,
            &[("SystemRoot", &system)],
            true,
            Some(job.as_handle()),
        )?;
        Ok(ScmJobFixtureChild {
            child,
            assignment: job,
        })
    }

    fn launch_suspended_with_observation(
        executable: &Path,
        command_line: &OsStr,
        environment: &[(&str, &str)],
        observable: bool,
        job: Option<BorrowedHandle<'_>>,
    ) -> Result<Self, IdentityDenied> {
        if !executable.is_absolute() || !executable.is_file() {
            return Err(IdentityDenied);
        }
        let app = wide(executable.as_os_str())?;
        let mut command = wide(command_line)?;
        let mut env = environment_block(environment)?;
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(IdentityDenied);
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let descriptors = if observable && job.is_some() {
            OwnerRightsCreationDescriptors::from_scm_issuer_job_primary_token(token.as_handle())?
        } else if observable {
            OwnerRightsCreationDescriptors::from_scm_issuer_primary_token(token.as_handle())?
        } else {
            OwnerRightsCreationDescriptors::from_primary_token(token.as_handle())?
        };
        let attributes = descriptors.borrow_attributes();

        if let Some(job) = job {
            use windows_sys::Win32::{
                Foundation::{
                    GetHandleInformation, GetLastError, ERROR_INSUFFICIENT_BUFFER,
                    HANDLE_FLAG_INHERIT,
                },
                System::{
                    Threading::{
                        DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
                        UpdateProcThreadAttribute, DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT,
                        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                        STARTUPINFOEXW,
                    },
                    WindowsProgramming::PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
                },
            };
            let mut flags = 0;
            if !observable
                || unsafe { GetHandleInformation(job.as_raw_handle(), &mut flags) } == 0
                || flags & HANDLE_FLAG_INHERIT != 0
            {
                return Err(IdentityDenied);
            }
            let job_handles = [job.as_raw_handle()];
            let child_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
            let mut needed = 0usize;
            if unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut needed) } != 0
                || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
                || !(1..=65536).contains(&needed)
            {
                return Err(IdentityDenied);
            }
            let mut storage = vec![0usize; needed.div_ceil(std::mem::size_of::<usize>())];
            let list = storage.as_mut_ptr().cast();
            if unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut needed) } == 0 {
                return Err(IdentityDenied);
            }
            struct Attributes(*mut std::ffi::c_void);
            impl Drop for Attributes {
                fn drop(&mut self) {
                    unsafe { DeleteProcThreadAttributeList(self.0) };
                }
            }
            let _list = Attributes(list);
            if unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                    job_handles.as_ptr().cast(),
                    std::mem::size_of_val(&job_handles),
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
                || unsafe {
                    UpdateProcThreadAttribute(
                        list,
                        0,
                        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY as usize,
                        (&child_policy as *const u32).cast(),
                        std::mem::size_of::<u32>(),
                        ptr::null_mut(),
                        ptr::null(),
                    )
                } == 0
            {
                return Err(IdentityDenied);
            }
            let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
            startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            startup.lpAttributeList = list;
            let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
            if unsafe {
                CreateProcessW(
                    app.as_ptr(),
                    command.as_mut_ptr(),
                    attributes.process(),
                    attributes.primary_thread(),
                    0,
                    CREATE_SUSPENDED
                        | DETACHED_PROCESS
                        | CREATE_UNICODE_ENVIRONMENT
                        | EXTENDED_STARTUPINFO_PRESENT,
                    env.as_mut_ptr().cast(),
                    ptr::null(),
                    &startup.StartupInfo,
                    &mut info,
                )
            } == 0
            {
                return Err(IdentityDenied);
            }
            return Self::from_process_information(info);
        }

        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let created = unsafe {
            CreateProcessW(
                app.as_ptr(),
                command.as_mut_ptr(),
                attributes.process(),
                attributes.primary_thread(),
                0,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                env.as_mut_ptr().cast(),
                ptr::null(),
                &startup,
                &mut info,
            )
        };
        if created == 0 {
            return Err(IdentityDenied);
        }
        Self::from_process_information(info)
    }

    fn from_process_information(info: PROCESS_INFORMATION) -> Result<Self, IdentityDenied> {
        // A partially populated PROCESS_INFORMATION must never strand an
        // unowned suspended process, even after an unexpected OS failure.
        if info.hProcess.is_null() || info.hThread.is_null() {
            if !info.hProcess.is_null() {
                unsafe {
                    TerminateProcess(info.hProcess, 1);
                    CloseHandle(info.hProcess)
                };
            }
            if !info.hThread.is_null() {
                unsafe { CloseHandle(info.hThread) };
            }
            return Err(IdentityDenied);
        }
        Ok(Self {
            process: unsafe { OwnedHandle::from_raw_handle(info.hProcess) },
            primary_thread: unsafe { OwnedHandle::from_raw_handle(info.hThread) },
            pid: info.dwProcessId,
            tid: info.dwThreadId,
            resumed: false,
            terminate_on_drop: true,
        })
    }

    /// Test-only current-token launch with one preconnected channel and one
    /// diagnostic file. Not a protected cross-principal issuer or a grant.
    #[cfg(test)]
    pub(crate) fn launch_suspended_with_local_channel(
        executable: &Path,
        command_line: &OsStr,
        environment: &[(&str, &str)],
        endpoint: BorrowedHandle<'_>,
        diagnostics: BorrowedHandle<'_>,
        job: &crate::windows_sdk_job::SdkJob,
    ) -> Result<Self, IdentityDenied> {
        let child = Self::launch_suspended_with_inherited_channel(
            executable,
            command_line,
            environment,
            endpoint,
            diagnostics,
            None,
            Some(job.as_handle()),
        )?;
        job.verify_member(child.process_handle())?;
        Ok(child)
    }

    #[cfg(test)]
    pub(crate) fn launch_suspended_with_local_service(
        executable: &Path,
        command_line: &OsStr,
        environment: &[(&str, &str)],
        endpoint: BorrowedHandle<'_>,
        diagnostics: BorrowedHandle<'_>,
        client_process: BorrowedHandle<'_>,
    ) -> Result<Self, IdentityDenied> {
        Self::launch_suspended_with_inherited_channel(
            executable,
            command_line,
            environment,
            endpoint,
            diagnostics,
            Some(client_process),
            None,
        )
    }

    #[cfg(test)]
    fn launch_suspended_with_inherited_channel(
        executable: &Path,
        command_line: &OsStr,
        environment: &[(&str, &str)],
        endpoint: BorrowedHandle<'_>,
        diagnostics: BorrowedHandle<'_>,
        client_process: Option<BorrowedHandle<'_>>,
        job: Option<BorrowedHandle<'_>>,
    ) -> Result<Self, IdentityDenied> {
        use windows_sys::Win32::{
            Foundation::{
                DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_INSUFFICIENT_BUFFER,
                HANDLE,
            },
            Storage::FileSystem::SYNCHRONIZE,
            System::Threading::{
                DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
                UpdateProcThreadAttribute, DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT,
                PROCESS_QUERY_LIMITED_INFORMATION, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                STARTF_USESTDHANDLES, STARTUPINFOEXW,
            },
            System::WindowsProgramming::PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
        };
        if !executable.is_absolute() || !executable.is_file() {
            return Err(IdentityDenied);
        }
        let app = wide(executable.as_os_str())?;
        let mut command = wide(command_line)?;
        let mut token = ptr::null_mut();
        let current = unsafe { GetCurrentProcess() };
        if unsafe { OpenProcessToken(current, TOKEN_QUERY, &mut token) } == 0 {
            return Err(IdentityDenied);
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let descriptors = OwnerRightsCreationDescriptors::from_primary_token(token.as_handle())?;
        let attributes = descriptors.borrow_attributes();

        // Only private duplicates are inheritable. The originals and other
        // fixture resources remain noninheritable and never enter this list.
        let duplicate = |source: BorrowedHandle<'_>| -> Result<OwnedHandle, IdentityDenied> {
            let mut result = ptr::null_mut();
            if unsafe {
                DuplicateHandle(
                    current,
                    source.as_raw_handle(),
                    current,
                    &mut result,
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
                || result.is_null()
            {
                return Err(IdentityDenied);
            }
            Ok(unsafe { OwnedHandle::from_raw_handle(result) })
        };
        let input = duplicate(endpoint)?;
        let output = duplicate(diagnostics)?;
        let mut handles: Vec<HANDLE> = vec![input.as_raw_handle(), output.as_raw_handle()];
        // A separate service inherits only reduced process handles in
        // addition to the connected server endpoint and diagnostics.
        let pin = |source: HANDLE| -> Result<OwnedHandle, IdentityDenied> {
            let mut result = ptr::null_mut();
            if unsafe {
                DuplicateHandle(
                    current,
                    source,
                    current,
                    &mut result,
                    PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                    1,
                    0,
                )
            } == 0
                || result.is_null()
            {
                return Err(IdentityDenied);
            }
            Ok(unsafe { OwnedHandle::from_raw_handle(result) })
        };
        let client_pin = client_process
            .map(|source| pin(source.as_raw_handle()))
            .transpose()?;
        let issuer_pin = if client_pin.is_some() {
            Some(pin(current)?)
        } else {
            None
        };
        let mut child_environment = environment.to_vec();
        if child_environment.iter().any(|(name, _)| {
            name.eq_ignore_ascii_case("JDC_T011_LOCAL_CLIENT_PIN")
                || name.eq_ignore_ascii_case("JDC_T011_LOCAL_ISSUER_PIN")
        }) {
            return Err(IdentityDenied);
        }
        let client_value;
        let issuer_value;
        if let (Some(client), Some(issuer)) = (&client_pin, &issuer_pin) {
            handles.extend([client.as_raw_handle(), issuer.as_raw_handle()]);
            client_value = (client.as_raw_handle() as usize).to_string();
            issuer_value = (issuer.as_raw_handle() as usize).to_string();
            // These values are indices into the inherited kernel handle
            // table, never independent identity attestations or grants.
            child_environment.push(("JDC_T011_LOCAL_CLIENT_PIN", &client_value));
            child_environment.push(("JDC_T011_LOCAL_ISSUER_PIN", &issuer_value));
        }
        let mut env = environment_block(&child_environment)?;
        // Attribute values must outlive the attribute list. The job handle
        // is not on the inheritable handle list; only the kernel associates
        // the new process with the job during CreateProcessW.
        let job_handles = job.map(|handle| [handle.as_raw_handle()]);
        let child_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        let count = if job.is_some() { 3 } else { 1 };
        let mut needed = 0usize;
        if unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut needed) } != 0
            || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
            || !(1..=65536).contains(&needed)
        {
            return Err(IdentityDenied);
        }
        let mut storage = vec![0usize; needed.div_ceil(std::mem::size_of::<usize>())];
        let list = storage.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut needed) } == 0 {
            return Err(IdentityDenied);
        }
        struct AttributeList(*mut std::ffi::c_void);
        impl Drop for AttributeList {
            fn drop(&mut self) {
                unsafe { DeleteProcThreadAttributeList(self.0) };
            }
        }
        let _list = AttributeList(list);
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles.as_slice()),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(IdentityDenied);
        }
        if let Some(job_handles) = &job_handles {
            if unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                    job_handles.as_ptr().cast(),
                    std::mem::size_of_val(job_handles),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } == 0
                || unsafe {
                    UpdateProcThreadAttribute(
                        list,
                        0,
                        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY as usize,
                        (&child_policy as *const u32).cast(),
                        std::mem::size_of_val(&child_policy),
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                } == 0
            {
                return Err(IdentityDenied);
            }
        }
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = input.as_raw_handle();
        startup.StartupInfo.hStdOutput = output.as_raw_handle();
        startup.StartupInfo.hStdError = output.as_raw_handle();
        startup.lpAttributeList = list;
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let created = unsafe {
            CreateProcessW(
                app.as_ptr(),
                command.as_mut_ptr(),
                attributes.process(),
                attributes.primary_thread(),
                1,
                CREATE_SUSPENDED
                    // A console host could consume the single job slot.
                    // All three standard handles are explicitly inherited.
                    | if job.is_some() { DETACHED_PROCESS } else { CREATE_NO_WINDOW }
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                env.as_mut_ptr().cast(),
                ptr::null(),
                &startup.StartupInfo,
                &mut info,
            )
        };
        if created == 0 {
            return Err(IdentityDenied);
        }
        Self::from_process_information(info)
    }

    /// Consume one issued ticket and serialize all native I/O and bounded
    /// overlapped pipe disclosure against policy revocation. No caller callback
    /// can leak an owned byte buffer or bypass the service-chosen transport.
    /// The caller must supply its own authenticated, OVERLAPPED native pipe.
    /// No arbitrary client pathname is reopened. This does not independently
    /// establish policy provenance, a trusted root or installed SCM authority.
    pub fn read_regular_into_pipe(
        &self,
        policy: &PolicyFence,
        ticket: &ReadTicket,
        pipe: BorrowedHandle<'_>,
        file: File,
        response_timeout: Duration,
    ) -> Result<(), IdentityDenied> {
        policy
            .execute_once(ticket, || {
                if !self.resumed {
                    return Err(IdentityDenied);
                }
                verify_live_issued_peer_after_read(pipe, self.process_handle())?;
                let client_sid = observe_client_sid_after_read(pipe)?;
                let issuer_sid = observe_process_sid()?;
                if client_sid != issuer_sid {
                    return Err(IdentityDenied);
                }
                let bytes = read_opened_regular(file).map_err(|_| IdentityDenied)?;
                disclose_bounded(pipe, &bytes, response_timeout)
            })
            .map_err(|_| IdentityDenied)?
    }

    pub fn process_handle(&self) -> BorrowedHandle<'_> {
        self.process.as_handle()
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn tid(&self) -> u32 {
        self.tid
    }
    pub fn primary_thread_identity(&self) -> Result<ThreadIdentity, IdentityDenied> {
        if self.resumed {
            return Err(IdentityDenied);
        }
        let stamp =
            ThreadIdentity::capture(self.process.as_handle(), self.primary_thread.as_handle())?;
        if stamp.pid != self.pid || stamp.tid != self.tid {
            return Err(IdentityDenied);
        }
        Ok(stamp)
    }

    pub fn resume(&mut self) -> Result<(), IdentityDenied> {
        if self.resumed || unsafe { ResumeThread(self.primary_thread.as_raw_handle()) } != 1 {
            return Err(IdentityDenied);
        }
        self.resumed = true;
        Ok(())
    }

    pub fn wait_for_exit(&self, duration: Duration) -> Result<(), IdentityDenied> {
        let milliseconds = u32::try_from(duration.as_millis()).map_err(|_| IdentityDenied)?;
        if milliseconds == 0 || milliseconds > 120_000 {
            return Err(IdentityDenied);
        }
        if unsafe { WaitForSingleObject(self.process.as_raw_handle(), milliseconds) }
            != WAIT_OBJECT_0
        {
            return Err(IdentityDenied);
        }
        Ok(())
    }

    pub fn exit_code(&self) -> Result<u32, IdentityDenied> {
        if unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } != WAIT_OBJECT_0 {
            return Err(IdentityDenied);
        }
        let mut code = u32::MAX;
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
            return Err(IdentityDenied);
        }
        Ok(code)
    }
}

impl Drop for IssuedClient {
    fn drop(&mut self) {
        if self.terminate_on_drop
            && unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } != WAIT_OBJECT_0
        {
            unsafe { TerminateProcess(self.process.as_raw_handle(), 1) };
            // Bound shutdown: never leave our test/managed child detached.
            // The process HANDLE still closes even if the wait fails.
            unsafe { WaitForSingleObject(self.process.as_raw_handle(), 5_000) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_primary_thread_identity_rejects_other_process_and_stale_creation() {
        let image = std::env::current_exe().unwrap();
        let command = format!("\"{}\"", image.display());
        let system = std::env::var("SystemRoot").unwrap();
        let launch = || {
            IssuedClient::launch_suspended(&image, OsStr::new(&command), &[("SystemRoot", &system)])
                .unwrap()
        };
        let child = launch();
        let other = launch();
        let stamp = child.primary_thread_identity().unwrap();
        assert_eq!(stamp.tid, child.tid());
        assert_eq!(stamp.pid, child.pid());
        use windows_sys::Win32::{
            Foundation::{DuplicateHandle, GetLastError, ERROR_ACCESS_DENIED},
            Storage::FileSystem::SYNCHRONIZE,
            System::Threading::THREAD_QUERY_LIMITED_INFORMATION,
        };
        let current = unsafe { GetCurrentProcess() };
        let mut raw = ptr::null_mut();
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    current,
                    child.primary_thread.as_raw_handle(),
                    current,
                    &mut raw,
                    THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                    0,
                    0,
                )
            },
            0
        );
        let pin = unsafe { OwnedHandle::from_raw_handle(raw) };
        assert_eq!(unsafe { ResumeThread(pin.as_raw_handle()) }, u32::MAX);
        assert_eq!(unsafe { GetLastError() }, ERROR_ACCESS_DENIED);
        let process = child.process_handle().try_clone_to_owned().unwrap();
        stamp.verify(process.as_handle(), pin.as_handle()).unwrap();
        assert!(stamp
            .verify(other.process_handle(), pin.as_handle())
            .is_err());
        assert!(stamp
            .verify(process.as_handle(), other.primary_thread.as_handle())
            .is_err());
        assert!(ThreadIdentity {
            creation: stamp.creation ^ 1,
            ..stamp
        }
        .verify(process.as_handle(), pin.as_handle())
        .is_err());
        drop(child);
        assert!(stamp.verify(process.as_handle(), pin.as_handle()).is_err());
    }

    #[test]
    fn malformed_environment_and_duplicate_variable_names_deny() {
        assert!(environment_block(&[]).is_err());
        assert!(environment_block(&[("A", "1"), ("a", "2")]).is_err());
        assert!(environment_block(&[("A=B", "x")]).is_err());
        assert!(environment_block(&[("A", "x\0y")]).is_err());
        assert!(environment_block(&[("", "x")]).is_err());
    }

    #[test]
    fn launcher_refuses_relative_images_and_embedded_command_nuls() {
        let environment = [("SystemRoot", "C:\\Windows")];
        let image = std::env::current_exe().unwrap();
        assert!(IssuedClient::launch_suspended(
            Path::new("relative-node.exe"),
            OsStr::new("relative-node.exe"),
            &environment,
        )
        .is_err());
        assert!(IssuedClient::launch_suspended(
            &image,
            OsStr::new("node.exe\0--untrusted"),
            &environment,
        )
        .is_err());
    }

    #[test]
    fn inherited_sdk_child_cannot_create_descendants() {
        use windows_sys::Win32::System::Threading::{
            GetProcessMitigationPolicy, ProcessChildProcessPolicy,
        };
        let image = std::env::current_exe().unwrap();
        let command = format!("\"{}\"", image.display());
        let system = std::env::var("SystemRoot").unwrap();
        let nul = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("NUL")
            .unwrap();
        let job = crate::windows_sdk_job::SdkJob::new_local().unwrap();
        let child = IssuedClient::launch_suspended_with_local_channel(
            &image,
            OsStr::new(&command),
            &[("SystemRoot", &system)],
            nul.as_handle(),
            nul.as_handle(),
            &job,
        )
        .unwrap();
        let mut policy = 0u32;
        assert_ne!(
            unsafe {
                GetProcessMitigationPolicy(
                    child.process_handle().as_raw_handle(),
                    ProcessChildProcessPolicy,
                    (&mut policy as *mut u32).cast(),
                    std::mem::size_of::<u32>(),
                )
            },
            0
        );
        assert_eq!(
            policy & 1,
            1,
            "the actual child token must prohibit child-process creation"
        );
    }

    #[test]
    fn fixture_job_sdk_child_rejects_descendant() {
        if std::env::var("JDC_T011_JOB_CHILD").as_deref() != Ok("1") {
            return;
        }
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.env_remove("JDC_T011_JOB_CHILD").args([
            "--exact",
            "windows_issued_client::tests::fixture_job_sdk_child_rejects_descendant",
        ]);
        match command.spawn() {
            Ok(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("SDK job permitted a descendant");
            }
            Err(error) => assert!(
                matches!(error.raw_os_error(), Some(5 | 1816 | 367)),
                "{error}"
            ),
        }
    }

    #[test]
    fn sdk_job_enforces_descendant_denial_and_terminal_cleanup() {
        let image = std::env::current_exe().unwrap();
        let target = "windows_issued_client::tests::fixture_job_sdk_child_rejects_descendant";
        assert!(std::process::Command::new(&image)
            .args(["--exact", target])
            .env_remove("JDC_T011_JOB_CHILD")
            .status()
            .unwrap()
            .success());
        let command = format!("\"{}\" --exact {target}", image.display());
        let system = std::env::var("SystemRoot").unwrap();
        let nul = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("NUL")
            .unwrap();
        let job = crate::windows_sdk_job::SdkJob::new_local().unwrap();
        let mut child = IssuedClient::launch_suspended_with_local_channel(
            &image,
            OsStr::new(&command),
            &[("SystemRoot", &system), ("JDC_T011_JOB_CHILD", "1")],
            nul.as_handle(),
            nul.as_handle(),
            &job,
        )
        .unwrap();
        child.resume().unwrap();
        child.wait_for_exit(Duration::from_secs(5)).unwrap();
        assert_eq!(child.exit_code(), Ok(0));
        job.verify_finished().unwrap();
    }

    // Discriminating nonrelease proof: the existing creation-time launcher
    // must accept an assignment-only job handle, not require authority's
    // control handle. This is a same-token kernel experiment, not SCM origin.
    #[test]
    fn sdk_job_assignment_handle_is_sufficient_without_control_rights() {
        use windows_sys::Win32::{
            Foundation::{DuplicateHandle, GetLastError, ERROR_ACCESS_DENIED},
            System::JobObjects::{
                JobObjectBasicAccountingInformation, QueryInformationJobObject,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
            },
            System::SystemServices::JOB_OBJECT_ASSIGN_PROCESS,
        };
        let job = crate::windows_sdk_job::SdkJob::new_local().unwrap();
        let current = unsafe { GetCurrentProcess() };
        let mut raw = ptr::null_mut();
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    current,
                    job.as_handle().as_raw_handle(),
                    current,
                    &mut raw,
                    JOB_OBJECT_ASSIGN_PROCESS,
                    0,
                    0,
                )
            },
            0
        );
        assert!(!raw.is_null());
        let assignment = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut counts = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        assert_eq!(
            unsafe {
                QueryInformationJobObject(
                    assignment.as_raw_handle(),
                    JobObjectBasicAccountingInformation,
                    (&mut counts as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_ACCESS_DENIED);
        let image = std::env::current_exe().unwrap();
        let command = format!("\"{}\"", image.display());
        let system = std::env::var("SystemRoot").unwrap();
        let nul = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("NUL")
            .unwrap();
        let child = IssuedClient::launch_suspended_with_inherited_channel(
            &image,
            OsStr::new(&command),
            &[("SystemRoot", &system)],
            nul.as_handle(),
            nul.as_handle(),
            None,
            Some(assignment.as_handle()),
        )
        .expect("assignment-only handle must be sufficient for creation-time membership");
        job.verify_member(child.process_handle()).unwrap();
        drop(assignment);
        assert!(child.exit_code().is_err());
        drop(job);
        child.wait_for_exit(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn sdk_job_handoff_preserves_child_until_authority_closes_last_handle() {
        let image = std::env::current_exe().unwrap();
        let command = format!("\"{}\"", image.display());
        let system = std::env::var("SystemRoot").unwrap();
        let nul = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("NUL")
            .unwrap();
        let job = crate::windows_sdk_job::SdkJob::new_local().unwrap();
        let child = IssuedClient::launch_suspended_with_local_channel(
            &image,
            OsStr::new(&command),
            &[("SystemRoot", &system)],
            nul.as_handle(),
            nul.as_handle(),
            &job,
        )
        .unwrap();
        let pin = child.process_handle().try_clone_to_owned().unwrap();
        let wrapper = ScmJobFixtureChild {
            child,
            assignment: job.as_handle().try_clone_to_owned().unwrap(),
        };
        wrapper.finish_verified_handoff().unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(pin.as_raw_handle(), 0) },
            windows_sys::Win32::Foundation::WAIT_TIMEOUT
        );
        job.verify_member(pin.as_handle()).unwrap();
        drop(job);
        assert_eq!(
            unsafe { WaitForSingleObject(pin.as_raw_handle(), 5000) },
            WAIT_OBJECT_0
        );
    }

    #[test]
    fn sdk_job_ordinary_caller_cannot_relinquish_cleanup() {
        let job = crate::windows_sdk_job::SdkJob::new_local().unwrap();
        assert!(IssuedClient::launch_scm_job_fixture(
            job.as_handle().try_clone_to_owned().unwrap()
        )
        .is_err());
        let image = std::env::current_exe().unwrap();
        let command = format!("\"{}\"", image.display());
        let system = std::env::var("SystemRoot").unwrap();
        let nul = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("NUL")
            .unwrap();
        let child = IssuedClient::launch_suspended_with_local_channel(
            &image,
            OsStr::new(&command),
            &[("SystemRoot", &system)],
            nul.as_handle(),
            nul.as_handle(),
            &job,
        )
        .unwrap();
        let pin = child.process_handle().try_clone_to_owned().unwrap();
        let wrapper = ScmJobFixtureChild {
            child,
            assignment: job.as_handle().try_clone_to_owned().unwrap(),
        };
        assert!(wrapper.relinquish().is_err());
        assert_eq!(
            unsafe { WaitForSingleObject(pin.as_raw_handle(), 5000) },
            WAIT_OBJECT_0
        );
        job.verify_finished().unwrap();
    }

    #[test]
    fn sdk_job_close_terminates_suspended_child_before_issuer_drop() {
        let image = std::env::current_exe().unwrap();
        let command = format!("\"{}\"", image.display());
        let system = std::env::var("SystemRoot").unwrap();
        let nul = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("NUL")
            .unwrap();
        let job = crate::windows_sdk_job::SdkJob::new_local().unwrap();
        let child = IssuedClient::launch_suspended_with_local_channel(
            &image,
            OsStr::new(&command),
            &[("SystemRoot", &system)],
            nul.as_handle(),
            nul.as_handle(),
            &job,
        )
        .unwrap();
        job.verify_member(child.process_handle()).unwrap();
        assert!(
            child.exit_code().is_err(),
            "child must remain suspended and live"
        );
        drop(job);
        child.wait_for_exit(Duration::from_secs(5)).unwrap();
        // Closing the last job handle can terminate with code zero.
        // A live suspended child becoming signaled without ResumeThread
        // or dropping the issuer handle is the required kernel evidence.
        assert!(child.exit_code().is_ok());
    }

    #[test]
    fn complete_sorted_unicode_environment_is_double_terminated() {
        let block = environment_block(&[("Z", "á"), ("SystemRoot", "C:\\Windows")]).unwrap();
        let text = String::from_utf16(&block).unwrap();
        assert_eq!(text, "SystemRoot=C:\\Windows\0Z=á\0\0");
    }
}
