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

/// The issuer alone retains both creation-time OS object handles. There is
/// deliberately no public constructor from a numeric PID or an arbitrary HANDLE.
pub struct IssuedClient {
    process: OwnedHandle,
    primary_thread: OwnedHandle,
    pid: u32,
    tid: u32,
    resumed: bool,
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
        Self::launch_suspended_with_observation(executable, command_line, environment, false)
    }

    /// Only the fixed SCM issuer role may create an observable proof child.
    /// This does not grant the observer a launch, thread or file capability.
    pub fn launch_scm_observable_fixture(
        executable: &Path,
        command_line: &OsStr,
        environment: &[(&str, &str)],
    ) -> Result<Self, IdentityDenied> {
        Self::launch_suspended_with_observation(executable, command_line, environment, true)
    }

    fn launch_suspended_with_observation(
        executable: &Path,
        command_line: &OsStr,
        environment: &[(&str, &str)],
        observable: bool,
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
        let descriptors = if observable {
            OwnerRightsCreationDescriptors::from_scm_issuer_primary_token(token.as_handle())?
        } else {
            OwnerRightsCreationDescriptors::from_primary_token(token.as_handle())?
        };
        let attributes = descriptors.borrow_attributes();

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
    ) -> Result<Self, IdentityDenied> {
        Self::launch_suspended_with_inherited_channel(
            executable,
            command_line,
            environment,
            endpoint,
            diagnostics,
            None,
        )
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
    ) -> Result<Self, IdentityDenied> {
        use windows_sys::Win32::{
            Foundation::{
                DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_INSUFFICIENT_BUFFER,
                HANDLE,
            },
            Storage::FileSystem::SYNCHRONIZE,
            System::Threading::{
                DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
                UpdateProcThreadAttribute, EXTENDED_STARTUPINFO_PRESENT,
                PROCESS_QUERY_LIMITED_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                STARTF_USESTDHANDLES, STARTUPINFOEXW,
            },
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
        let mut needed = 0usize;
        if unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut needed) } != 0
            || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
            || !(1..=65536).contains(&needed)
        {
            return Err(IdentityDenied);
        }
        let mut storage = vec![0usize; needed.div_ceil(std::mem::size_of::<usize>())];
        let list = storage.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut needed) } == 0 {
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
                    | CREATE_NO_WINDOW
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
        if unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } != WAIT_OBJECT_0 {
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
    fn complete_sorted_unicode_environment_is_double_terminated() {
        let block = environment_block(&[("Z", "á"), ("SystemRoot", "C:\\Windows")]).unwrap();
        let text = String::from_utf16(&block).unwrap();
        assert_eq!(text, "SystemRoot=C:\\Windows\0Z=á\0\0");
    }
}
