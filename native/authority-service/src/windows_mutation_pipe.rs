//! Nonshipping, bounded named-pipe transport for the local mutation proof.
//! Not a cross-principal issuer or grant. The trusted fixture creates the
//! pipe and owns the guarded process throughout the exchange. The connector
//! PID does not alone authenticate a writer of a delegated handle.
use crate::{
    windows_pipe_peer::{observe_client_sid_after_read, verify_live_issued_peer_after_read},
    IdentityDenied,
};
use std::{
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, OwnedHandle},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::WAIT_TIMEOUT,
    System::{
        Pipes::{DisconnectNamedPipe, GetNamedPipeClientProcessId, PeekNamedPipe},
        Threading::{GetProcessId, WaitForSingleObject},
    },
};
pub(super) struct MutationPipe(OwnedHandle);
#[path = "windows_bounded_pipe_io.rs"]
mod bounded_io;
use bounded_io::{deadline, Progress};
#[cfg(test)]
use bounded_io::{event, finish};
#[cfg(test)]
use std::os::windows::io::FromRawHandle;
#[cfg(test)]
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        ReadFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
    },
    System::{
        Pipes::{
            CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
            PIPE_WAIT,
        },
        IO::OVERLAPPED,
    },
};
impl MutationPipe {
    #[cfg(feature = "scm-storage-proof")]
    pub(super) fn from_scm_fixture(handle: OwnedHandle) -> Result<Self, IdentityDenied> {
        crate::windows_token::verify_scm_fixture_identity(
            crate::windows_token::ScmFixtureRole::Authority,
        )
        .map_err(|_| IdentityDenied)?;
        // The fixed proof controller has already checked the actual
        // descriptor, first-instance creation and noninheritability.
        Ok(Self(handle))
    }

    #[cfg(test)]
    pub(super) fn create(name: &str, first: bool) -> Result<Self, IdentityDenied> {
        Self::create_with_instances(name, first, 2)
    }
    #[cfg(test)]
    fn create_with_instances(
        name: &str,
        first: bool,
        instances: u32,
    ) -> Result<Self, IdentityDenied> {
        Self::create_with_descriptor(name, first, instances, ptr::null())
    }

    #[cfg(test)]
    fn create_with_descriptor(
        name: &str,
        first: bool,
        instances: u32,
        security: *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    ) -> Result<Self, IdentityDenied> {
        if !name.starts_with(r"\\.\pipe\JDC-T011-MUTATION-")
            || name.len() > 200
            || name.contains('\0')
        {
            return Err(IdentityDenied);
        }
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // Default local fixture DACL only; independent-principal pipe
        // custody must be supplied by the protected hosted issuer.
        let raw = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX
                    | FILE_FLAG_OVERLAPPED
                    | if first {
                        FILE_FLAG_FIRST_PIPE_INSTANCE
                    } else {
                        0
                    },
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                instances,
                8192,
                8192,
                0,
                security,
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(IdentityDenied);
        }
        Ok(Self(unsafe { OwnedHandle::from_raw_handle(raw) }))
    }
    // Same-token local experiment with the exact admitted SCM read client
    // mask. The creator retains the server handle, but the client principal
    // has no generic-write or instance-creation ACE. Not an SCM grant.
    #[cfg(test)]
    pub(super) fn create_limited_local(name: &str) -> Result<Self, IdentityDenied> {
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::{
                Authorization::{
                    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                },
                SECURITY_ATTRIBUTES,
            },
        };
        struct Local(*mut std::ffi::c_void);
        impl Drop for Local {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe {
                        LocalFree(self.0);
                    }
                }
            }
        }
        if !(name.ends_with("-fresh") || name.ends_with("-fresh-completion")) {
            return Err(IdentityDenied);
        }
        let sid = crate::windows_pipe_peer::observe_process_sid()?;
        let mut aligned = vec![0usize; sid.len().div_ceil(std::mem::size_of::<usize>())];
        unsafe {
            ptr::copy_nonoverlapping(sid.as_ptr(), aligned.as_mut_ptr().cast::<u8>(), sid.len());
        }
        let mut text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(aligned.as_mut_ptr().cast(), &mut text) } == 0
            || text.is_null()
        {
            return Err(IdentityDenied);
        }
        let _text = Local(text.cast());
        let len = (0..=184)
            .find(|&i| unsafe { *text.add(i) == 0 })
            .ok_or(IdentityDenied)?;
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })
            .map_err(|_| IdentityDenied)?;
        // SYSTEM would be a full-access control, not a limited-client proof.
        if sid == "S-1-5-18" {
            return Err(IdentityDenied);
        }
        let sddl = format!("D:P(A;;GA;;;SY)(A;;RC;;;OW)(A;;0x0012019B;;;{sid})");
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
        let sd = Local(raw);
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        Self::create_with_descriptor(name, true, 1, &sa)
    }

    pub(super) fn await_ready(
        &self,
        issued: BorrowedHandle<'_>,
        sid: &[u8],
    ) -> Result<(), IdentityDenied> {
        let mut ready = [0u8; 1];
        self.read_attested(
            issued,
            sid,
            &mut ready,
            deadline(Duration::from_secs(5))?,
            &mut |_| {},
        )?;
        if ready != *b"R" {
            return Err(IdentityDenied);
        }
        Ok(())
    }

    pub(super) fn connect(&self, timeout: Duration) -> Result<(), IdentityDenied> {
        bounded_io::connect(self.0.as_handle(), deadline(timeout)?)
    }
    // This server owns an overlapped pipe. A disconnected peer, unread
    // input or an unobservable state must deny publication. This is a
    // boundary observation, not atomic exclusion of a later disconnect.
    fn peer_open_for_commit(&self) -> bool {
        let mut available = 0;
        let observed = unsafe {
            PeekNamedPipe(
                self.0.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut available,
                ptr::null_mut(),
            )
        };
        observed != 0 && available == 0
    }

    pub(super) fn commit_allowed(&self, issued: BorrowedHandle<'_>, sid: &[u8]) -> bool {
        self.peer_open_for_commit()
            && verify_live_issued_peer_after_read(self.0.as_handle(), issued).is_ok()
            && observe_client_sid_after_read(self.0.as_handle()).is_ok_and(|actual| actual == sid)
            && self.peer_open_for_commit()
    }

    pub(super) fn challenge(&self, issued: BorrowedHandle<'_>) -> Result<(), IdentityDenied> {
        let mut connector = 0;
        if unsafe { GetNamedPipeClientProcessId(self.0.as_raw_handle(), &mut connector) } == 0
            || connector == 0
            || unsafe { GetProcessId(issued.as_raw_handle()) } != connector
            || unsafe { WaitForSingleObject(issued.as_raw_handle(), 0) } != WAIT_TIMEOUT
        {
            return Err(IdentityDenied);
        }
        crate::windows_pipe_disclosure::write_chunk(self.0.as_handle(), b"C", 3000)
    }
    fn read_attested(
        &self,
        issued: BorrowedHandle<'_>,
        sid: &[u8],
        data: &mut [u8],
        end: Instant,
        progress: &mut impl FnMut(Progress),
    ) -> Result<(), IdentityDenied> {
        self.read_checked(data, end, progress, || {
            verify_live_issued_peer_after_read(self.0.as_handle(), issued)?;
            if observe_client_sid_after_read(self.0.as_handle())? != sid {
                return Err(IdentityDenied);
            }
            Ok(())
        })
    }
    fn read_checked(
        &self,
        data: &mut [u8],
        end: Instant,
        progress: &mut impl FnMut(Progress),
        attest: impl FnMut() -> Result<(), IdentityDenied>,
    ) -> Result<(), IdentityDenied> {
        bounded_io::read_checked(self.0.as_handle(), data, end, progress, attest)
    }
    pub(super) fn receive(
        &self,
        issued: BorrowedHandle<'_>,
        sid: &[u8],
        limit: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, IdentityDenied> {
        self.receive_observed(issued, sid, limit, timeout, |_| {})
    }
    fn receive_observed(
        &self,
        issued: BorrowedHandle<'_>,
        sid: &[u8],
        limit: usize,
        timeout: Duration,
        mut progress: impl FnMut(Progress),
    ) -> Result<Vec<u8>, IdentityDenied> {
        if limit == 0 || limit > 1024 * 1024 + 8192 || sid.is_empty() {
            return Err(IdentityDenied);
        }
        let end = deadline(timeout)?;
        let mut header = [0u8; 4];
        self.read_attested(issued, sid, &mut header, end, &mut progress)?;
        let size = u32::from_be_bytes(header) as usize;
        if size == 0 || size > limit {
            return Err(IdentityDenied);
        }
        let mut payload = vec![0u8; size];
        self.read_attested(issued, sid, &mut payload, end, &mut progress)?;
        Ok(payload)
    }
    // Fresh connector: verify actual cancellation from the pinned process
    // at the staged boundary before disconnecting. Never accept an unrelated
    // close, timeout, or an unauthenticated cancellation byte as proof.
    pub(super) fn observe_staged_cancellation(
        &self,
        issued: BorrowedHandle<'_>,
        sid: &[u8],
    ) -> Result<(), IdentityDenied> {
        if !self.commit_allowed(issued, sid) {
            return Err(IdentityDenied);
        }
        crate::windows_pipe_disclosure::write_chunk(self.0.as_handle(), b"S", 3000)?;
        let mut cancellation = [0u8; 1];
        self.read_attested(
            issued,
            sid,
            &mut cancellation,
            deadline(Duration::from_secs(5))?,
            &mut |_| {},
        )?;
        if cancellation != *b"X" || !self.commit_allowed(issued, sid) {
            return Err(IdentityDenied);
        }
        if unsafe { DisconnectNamedPipe(self.0.as_raw_handle()) } == 0
            || self.commit_allowed(issued, sid)
        {
            return Err(IdentityDenied);
        }
        if unsafe { WaitForSingleObject(issued.as_raw_handle(), 0) } != WAIT_TIMEOUT {
            return Err(IdentityDenied);
        }
        Ok(())
    }

    // Test-only terminal synchronization. This is not the mutation channel
    // and never grants authority. Verify the real issued peer on both reads.
    pub(super) fn confirm_cancelled(
        &self,
        issued: BorrowedHandle<'_>,
        sid: &[u8],
    ) -> Result<(), IdentityDenied> {
        let mut ready = [0u8; 1];
        self.read_attested(
            issued,
            sid,
            &mut ready,
            deadline(Duration::from_secs(5))?,
            &mut |_| {},
        )?;
        if ready != *b"R" {
            return Err(IdentityDenied);
        }
        crate::windows_pipe_disclosure::write_chunk(self.0.as_handle(), b"V", 3000)?;
        let mut ack = [0u8; 1];
        self.read_attested(
            issued,
            sid,
            &mut ack,
            deadline(Duration::from_secs(3))?,
            &mut |_| {},
        )?;
        if ack != *b"K" {
            return Err(IdentityDenied);
        }
        Ok(())
    }

    pub(super) fn reply(
        &self,
        issued: BorrowedHandle<'_>,
        sid: &[u8],
        byte: u8,
    ) -> Result<(), IdentityDenied> {
        if !matches!(byte, b'A' | b'D') {
            return Err(IdentityDenied);
        }
        crate::windows_pipe_disclosure::write_chunk(self.0.as_handle(), &[byte], 3000)?;
        // Bounded acknowledgment proves the client read the reply before
        // we close the instance. No unbounded FlushFileBuffers is used.
        let mut ack = [0u8; 1];
        self.read_attested(
            issued,
            sid,
            &mut ack,
            deadline(Duration::from_secs(3))?,
            &mut |_| {},
        )?;
        if ack != *b"K" {
            return Err(IdentityDenied);
        }
        Ok(())
    }
}

/// Distinct transport for a preconnected, issuer-owned channel. Connector
/// PID and pipe impersonation cannot identify its later writer. This local
/// experiment does not establish protected issuer or distinct-token custody.
/// The channel retains the exact creation-time process object with reduced
/// rights; callers cannot substitute another process for individual requests.
#[cfg(test)]
pub(super) struct IssuerConnectedMutationPipe {
    pipe: MutationPipe,
    issued_process: OwnedHandle,
    issuer_process: Option<OwnedHandle>,
}

#[cfg(test)]
impl IssuerConnectedMutationPipe {
    pub(super) fn issue_local(
        name: &str,
        executable: &std::path::Path,
        command: &std::ffi::OsStr,
        environment: &[(&str, &str)],
        diagnostics: BorrowedHandle<'_>,
        job: &crate::windows_sdk_job::SdkJob,
    ) -> Result<(Self, crate::windows_issued_client::IssuedClient), IdentityDenied> {
        use crate::windows_issued_client::IssuedClient;
        use windows_sys::Win32::{
            Foundation::{CompareObjectHandles, DuplicateHandle},
            Storage::FileSystem::SYNCHRONIZE,
            System::Threading::{GetCurrentProcess, PROCESS_QUERY_LIMITED_INFORMATION},
        };
        let (pipe, endpoint) = Self::local_pair(name)?;
        let child = IssuedClient::launch_suspended_with_local_channel(
            executable,
            command,
            environment,
            endpoint.as_handle(),
            diagnostics,
            job,
        )?;
        // Close the issuer's client-end copy before any protocol traffic.
        drop(endpoint);
        let current = unsafe { GetCurrentProcess() };
        let mut reduced = ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                current,
                child.process_handle().as_raw_handle(),
                current,
                &mut reduced,
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                0,
                0,
            )
        } == 0
            || reduced.is_null()
        {
            return Err(IdentityDenied);
        }
        let issued_process = unsafe { OwnedHandle::from_raw_handle(reduced) };
        if unsafe {
            CompareObjectHandles(
                issued_process.as_raw_handle(),
                child.process_handle().as_raw_handle(),
            )
        } == 0
        {
            return Err(IdentityDenied);
        }
        let channel = Self {
            pipe,
            issued_process,
            issuer_process: None,
        };
        if !channel.is_live() {
            return Err(IdentityDenied);
        }
        Ok((channel, child))
    }

    /// Transfer the connected server endpoint and reduced client/issuer
    /// process handles to a separate same-token test service. The launcher
    /// owns the explicit inheritance list, and this consumes its copies.
    pub(super) fn launch_local_service(
        self,
        executable: &std::path::Path,
        command: &std::ffi::OsStr,
        environment: &[(&str, &str)],
        diagnostics: BorrowedHandle<'_>,
    ) -> Result<crate::windows_issued_client::IssuedClient, IdentityDenied> {
        let mut connector = 0;
        if self.issuer_process.is_some()
            || !self.is_live()
            || unsafe { GetNamedPipeClientProcessId(self.pipe.0.as_raw_handle(), &mut connector) }
                == 0
            || connector != std::process::id()
        {
            return Err(IdentityDenied);
        }
        crate::windows_issued_client::IssuedClient::launch_suspended_with_local_service(
            executable,
            command,
            environment,
            self.pipe.0.as_handle(),
            diagnostics,
            self.issued_process.as_handle(),
        )
    }

    /// The numeric environment values are only indices into handles that
    /// the trusted local fixture actually inherited at process creation.
    /// Validate object types, inheritance, origin, and liveness. Never use
    /// this constructor for production or as a cross-principal grant.
    pub(super) fn from_local_service() -> Result<Self, IdentityDenied> {
        use windows_sys::Win32::{
            Foundation::{
                DuplicateHandle, GetHandleInformation, SetHandleInformation, DUPLICATE_SAME_ACCESS,
                HANDLE, HANDLE_FLAG_INHERIT,
            },
            Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE, SYNCHRONIZE},
            System::{
                Pipes::{GetNamedPipeInfo, PIPE_SERVER_END},
                Threading::{GetCurrentProcess, PROCESS_QUERY_LIMITED_INFORMATION},
            },
        };
        let raw_pipe = std::io::stdin().as_raw_handle();
        let inherited_pin = |name: &str| -> Result<HANDLE, IdentityDenied> {
            let value = std::env::var(name).map_err(|_| IdentityDenied)?;
            let raw = value.parse::<usize>().map_err(|_| IdentityDenied)? as HANDLE;
            if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                return Err(IdentityDenied);
            }
            Ok(raw)
        };
        let client = inherited_pin("JDC_T011_LOCAL_CLIENT_PIN")?;
        let issuer = inherited_pin("JDC_T011_LOCAL_ISSUER_PIN")?;
        if raw_pipe.is_null()
            || raw_pipe == INVALID_HANDLE_VALUE
            || client == issuer
            || client == raw_pipe
            || issuer == raw_pipe
        {
            return Err(IdentityDenied);
        }
        for raw in [raw_pipe, client, issuer] {
            let mut flags = 0;
            if unsafe { GetHandleInformation(raw, &mut flags) } == 0
                || flags & HANDLE_FLAG_INHERIT == 0
                || unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, 0) } == 0
            {
                return Err(IdentityDenied);
            }
        }
        let mut pipe_flags = 0;
        let mut connector = 0;
        let client_id = unsafe { GetProcessId(client) };
        let issuer_id = unsafe { GetProcessId(issuer) };
        if unsafe { GetFileType(raw_pipe) } != FILE_TYPE_PIPE
            || unsafe {
                GetNamedPipeInfo(
                    raw_pipe,
                    &mut pipe_flags,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } == 0
            || pipe_flags & PIPE_SERVER_END == 0
            || unsafe { GetNamedPipeClientProcessId(raw_pipe, &mut connector) } == 0
            || connector != issuer_id
            || issuer_id == 0
            || client_id == 0
            || issuer_id == client_id
            || issuer_id == std::process::id()
            || client_id == std::process::id()
        {
            return Err(IdentityDenied);
        }
        // The original inherited handles are non-inheritable now and live
        // until this test process exits. Own independent reduced duplicates
        // for the Rust service object; never adopt an unvalidated integer.
        let current = unsafe { GetCurrentProcess() };
        let duplicate =
            |raw: HANDLE, access: u32, options: u32| -> Result<OwnedHandle, IdentityDenied> {
                let mut result = ptr::null_mut();
                if unsafe {
                    DuplicateHandle(current, raw, current, &mut result, access, 0, options)
                } == 0
                    || result.is_null()
                {
                    return Err(IdentityDenied);
                }
                Ok(unsafe { OwnedHandle::from_raw_handle(result) })
            };
        let pipe = duplicate(raw_pipe, 0, DUPLICATE_SAME_ACCESS)?;
        let issued_process = duplicate(client, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0)?;
        let issuer_process = duplicate(issuer, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0)?;
        let own_sid = crate::windows_pipe_peer::observe_process_sid()?;
        if crate::windows_pipe_peer::observe_process_handle_sid(issued_process.as_handle())?
            != own_sid
            || crate::windows_pipe_peer::observe_process_handle_sid(issuer_process.as_handle())?
                != own_sid
        {
            return Err(IdentityDenied);
        }
        let channel = Self {
            pipe: MutationPipe(pipe),
            issued_process,
            issuer_process: Some(issuer_process),
        };
        if !channel.is_live() {
            return Err(IdentityDenied);
        }
        Ok(channel)
    }

    fn local_pair(name: &str) -> Result<(MutationPipe, OwnedHandle), IdentityDenied> {
        use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
        };
        let pipe = MutationPipe::create_with_instances(name, true, 1)?;
        // Connect ourselves before issuance. No client-side path open and
        // no FILE_CREATE_PIPE_INSTANCE grant on the inherited endpoint.
        let client = OpenOptions::new()
            .access_mode(0x0012019B)
            .custom_flags(FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
            .open(name)
            .map_err(|_| IdentityDenied)?;
        pipe.connect(Duration::from_secs(3))?;
        let mut connector = 0;
        if unsafe { GetNamedPipeClientProcessId(pipe.0.as_raw_handle(), &mut connector) } == 0
            || connector != std::process::id()
        {
            return Err(IdentityDenied);
        }
        Ok((pipe, client.into()))
    }

    pub(super) fn matches_issued_process(&self, candidate: BorrowedHandle<'_>) -> bool {
        use windows_sys::Win32::Foundation::CompareObjectHandles;
        self.is_live()
            && unsafe {
                CompareObjectHandles(
                    self.issued_process.as_raw_handle(),
                    candidate.as_raw_handle(),
                )
            } != 0
    }

    pub(super) fn is_live(&self) -> bool {
        let live = |process: &OwnedHandle| {
            (unsafe { GetProcessId(process.as_raw_handle()) }) != 0
                && unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } == WAIT_TIMEOUT
        };
        live(&self.issued_process) && self.issuer_process.as_ref().is_none_or(live)
    }

    fn ensure_live(&self) -> Result<(), IdentityDenied> {
        if self.is_live() {
            Ok(())
        } else {
            Err(IdentityDenied)
        }
    }

    /// Readiness is a synchronization signal, never an identity or grant.
    pub(super) fn await_ready(&self) -> Result<(), IdentityDenied> {
        let mut ready = [0u8; 1];
        self.pipe.read_checked(
            &mut ready,
            deadline(Duration::from_secs(25))?,
            &mut |_| {},
            || self.ensure_live(),
        )?;
        if ready != *b"R" {
            return Err(IdentityDenied);
        }
        Ok(())
    }
    pub(super) fn challenge(&self) -> Result<(), IdentityDenied> {
        self.ensure_live()?;
        crate::windows_pipe_disclosure::write_chunk(self.pipe.0.as_handle(), b"C", 3000)
    }
    pub(super) fn receive(
        &self,
        limit: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, IdentityDenied> {
        if limit == 0 || limit > 1024 * 1024 + 8192 {
            return Err(IdentityDenied);
        }
        let end = deadline(timeout)?;
        let mut header = [0u8; 4];
        self.pipe
            .read_checked(&mut header, end, &mut |_| {}, || self.ensure_live())?;
        let size = u32::from_be_bytes(header) as usize;
        if size == 0 || size > limit {
            return Err(IdentityDenied);
        }
        let mut payload = vec![0; size];
        self.pipe
            .read_checked(&mut payload, end, &mut |_| {}, || self.ensure_live())?;
        Ok(payload)
    }
    pub(super) fn commit_allowed(&self) -> bool {
        self.is_live() && self.pipe.peer_open_for_commit() && self.is_live()
    }

    /// Report the staged boundary and require explicit cancellation over the
    /// inherited channel. libuv retains the original standard descriptor on
    /// Windows, so socket destruction alone is not a reliable EOF signal.
    /// Disconnect the native endpoint before permitting any further work.
    pub(super) fn observe_staged_cancellation(&self) -> Result<(), IdentityDenied> {
        self.ensure_live()?;
        crate::windows_pipe_disclosure::write_chunk(self.pipe.0.as_handle(), b"S", 3000)?;
        let mut cancellation = [0u8; 1];
        self.pipe.read_checked(
            &mut cancellation,
            deadline(Duration::from_secs(5))?,
            &mut |_| {},
            || self.ensure_live(),
        )?;
        if cancellation != *b"X" || !self.pipe.peer_open_for_commit() {
            return Err(IdentityDenied);
        }
        if unsafe { DisconnectNamedPipe(self.pipe.0.as_raw_handle()) } == 0 || self.commit_allowed()
        {
            return Err(IdentityDenied);
        }
        self.ensure_live()
    }

    pub(super) fn reply(&self, byte: u8) -> Result<(), IdentityDenied> {
        self.ensure_live()?;
        if !matches!(byte, b'A' | b'D') {
            return Err(IdentityDenied);
        }
        crate::windows_pipe_disclosure::write_chunk(self.pipe.0.as_handle(), &[byte], 3000)?;
        let mut ack = [0u8; 1];
        self.pipe.read_checked(
            &mut ack,
            deadline(Duration::from_secs(3))?,
            &mut |_| {},
            || self.ensure_live(),
        )?;
        if ack != *b"K" {
            return Err(IdentityDenied);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::OpenOptions,
        os::windows::fs::OpenOptionsExt,
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        Storage::FileSystem::{SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT},
        System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    };
    #[test]
    fn commit_gate_denies_closed_or_unexpected_input_even_with_live_process() {
        let name = format!(
            r"\\.\pipe\JDC-T011-MUTATION-{}-{}-commit",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let (pipe, endpoint) = IssuerConnectedMutationPipe::local_pair(&name).unwrap();
        assert!(pipe.peer_open_for_commit());
        crate::windows_pipe_disclosure::write_chunk(endpoint.as_handle(), b"X", 2000).unwrap();
        assert!(!pipe.peer_open_for_commit());
        let mut byte = [0];
        pipe.read_checked(
            &mut byte,
            deadline(Duration::from_secs(2)).unwrap(),
            &mut |_| {},
            || Ok(()),
        )
        .unwrap();
        assert_eq!(byte, *b"X");
        assert!(pipe.peer_open_for_commit());
        drop(endpoint);
        assert!(!pipe.peer_open_for_commit());
    }

    #[test]
    fn actual_pipe_frames_reject_wrong_sid_oversize() {
        actual_pipe_frames(0..3);
    }
    #[test]
    fn actual_pipe_frames_reject_truncation_on_peer_close() {
        actual_pipe_frames(3..4);
    }
    #[test]
    fn actual_pipe_frames_reject_stall_on_cancelled_timeout() {
        actual_pipe_frames(4..5);
    }
    fn actual_pipe_frames(modes: std::ops::Range<u8>) {
        let pid = unsafe { GetCurrentProcessId() };
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x00100000, 0, pid) };
        assert!(!raw.is_null());
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        let sid = crate::windows_pipe_peer::observe_process_sid().unwrap();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Same-process local transport tests only; not process custody.
        for mode in modes {
            let name = format!(r"\\.\pipe\JDC-T011-MUTATION-{pid}-{unique}-{mode}");
            std::thread::scope(|scope| {
                // All owned handles/channels close before scope joins on unwind.
                let pipe = MutationPipe::create(&name, true).unwrap();
                let (hold, release) = std::sync::mpsc::channel();
                let (partial, received) = std::sync::mpsc::channel();
                scope.spawn(move || {
                    let client = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .custom_flags(
                            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED,
                        )
                        .open(name)
                        .unwrap();
                    let mut challenge = [0u8; 1];
                    let event = event().unwrap();
                    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
                    ov.hEvent = event.as_raw_handle();
                    let started = unsafe {
                        ReadFile(
                            client.as_raw_handle(),
                            challenge.as_mut_ptr(),
                            1,
                            ptr::null_mut(),
                            &mut ov,
                        )
                    };
                    assert_eq!(
                        finish(client.as_handle(), &mut ov, started, 2000, |_| {}),
                        Ok(1)
                    );
                    assert_eq!(challenge, *b"C");
                    let write = |bytes: &[u8]| {
                        crate::windows_pipe_disclosure::write_chunk(client.as_handle(), bytes, 2000)
                            .unwrap()
                    };
                    match mode {
                        0 | 3 => {
                            write(&5u32.to_be_bytes());
                            write(b"AB");
                            // Do not write the suffix/close until the server
                            // actually observed both partial payload bytes.
                            received.recv_timeout(Duration::from_secs(3)).unwrap();
                            if mode == 3 {
                                return;
                            }
                            write(b"CDE");
                        }
                        1 => write(&5u32.to_be_bytes()),
                        2 => write(&6u32.to_be_bytes()),
                        _ => {}
                    }
                    release.recv_timeout(Duration::from_secs(3)).unwrap();
                });
                pipe.connect(Duration::from_secs(2)).unwrap();
                pipe.challenge(process.as_handle()).unwrap();
                let wrong = vec![1, 0, 0, 0, 0, 0, 0, 0];
                let expected = if mode == 1 { &wrong } else { &sid };
                let timeout = if mode == 4 {
                    Duration::from_millis(100)
                } else {
                    Duration::from_secs(2)
                };
                let mut observed = Vec::new();
                let mut bytes = 0;
                let result =
                    pipe.receive_observed(process.as_handle(), expected, 5, timeout, |event| {
                        observed.push(event);
                        if let Progress::Bytes(n) = event {
                            bytes += n;
                            if matches!(mode, 0 | 3) && bytes == 6 {
                                partial.send(()).unwrap();
                            }
                        }
                    });
                if mode == 0 {
                    assert_eq!(result, Ok(b"ABCDE".to_vec()));
                    assert_eq!(bytes, 9);
                } else {
                    assert_eq!(result, Err(IdentityDenied));
                }
                match mode {
                    0 => assert!(observed.len() >= 3),
                    1 => assert!(observed.is_empty()),
                    2 => assert_eq!(bytes, 4),
                    3 => {
                        assert_eq!(bytes, 6);
                        assert_eq!(observed.last(), Some(&Progress::PeerClosed));
                    }
                    4 => assert_eq!(observed, [Progress::PendingTimeoutCancelled]),
                    _ => unreachable!(),
                }
                if mode != 3 {
                    hold.send(()).unwrap();
                }
            });
        }
    }
}
