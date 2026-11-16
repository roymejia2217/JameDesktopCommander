//! Non-shipping T011 Windows named-pipe token proof on disposable CI accounts.
//! NOT an SCM service, production IPC framing, root authorization or MCP route.
#[cfg(windows)]
mod proof {
    use jdc_authority_service::windows_pipe_peer::{
        observe_client_sid_after_read, observe_process_sid,
    };
    use std::{ffi::c_void, mem::size_of, ptr};
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND,
            ERROR_INVALID_PARAMETER, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE,
            INVALID_HANDLE_VALUE,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
            },
            GetLengthSid, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE,
            OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
        },
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW,
            PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
    };

    type Result<T> = std::result::Result<T, &'static str>;
    const READ_WRITE_DATA: u32 = 0x0003;
    // Standard file read/write rights minus FILE_APPEND_DATA (0x4).
    // This retains standard READ_CONTROL and attribute rights while refusing
    // FILE_CREATE_PIPE_INSTANCE, which aliases FILE_APPEND_DATA for pipes.
    // Never grant generic file-write rights directly to a client.
    const CLIENT_PIPE_RIGHTS: &str = "0x0012019B";
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct LocalMemory(*mut c_void);
    impl Drop for LocalMemory {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    fn sid(value: &str) -> Result<Vec<u8>> {
        if !value.starts_with("S-1-5-") || value.len() > 192 {
            return Err("E_PIPE_SID");
        }
        let mut ptr = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide(value).as_ptr(), &mut ptr) } == 0 || ptr.is_null() {
            return Err("E_PIPE_SID_PARSE");
        }
        let _owned = LocalMemory(ptr);
        let len = unsafe { GetLengthSid(ptr) } as usize;
        if !(12..=256).contains(&len) {
            return Err("E_PIPE_SID_LENGTH");
        }
        let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
        if jdc_authority_service::token_policy::bounded_sid_bytes(bytes) != Some(len) {
            return Err("E_PIPE_SID_MALFORMED");
        }
        Ok(bytes.to_vec())
    }
    fn pipe_name(value: &str) -> Result<Vec<u16>> {
        let Some(unique) = value.strip_prefix(r"\\.\pipe\JDC-T011-") else {
            return Err("E_PIPE_LOCAL_NAME");
        };
        if unique.len() < 12
            || unique.len() > 64
            || !unique
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("E_PIPE_NAME_UNSAFE");
        }
        Ok(wide(value))
    }

    fn write_one(pipe: HANDLE, byte: u8) -> Result<()> {
        let mut written = 0u32;
        if unsafe { WriteFile(pipe, &byte, 1, &mut written, ptr::null_mut()) } == 0 || written != 1
        {
            return Err("E_PIPE_WRITE");
        }
        Ok(())
    }
    fn read_one(pipe: HANDLE) -> Result<u8> {
        let mut byte = 0u8;
        let mut received = 0u32;
        if unsafe { ReadFile(pipe, &mut byte, 1, &mut received, ptr::null_mut()) } == 0
            || received != 1
        {
            return Err("E_PIPE_READ");
        }
        Ok(byte)
    }
    fn security_descriptor(service: &str, client: &str) -> Result<LocalMemory> {
        // Stronger kernel boundary: only the dedicated client SID may open
        // a data channel. No Everyone/Anonymous or foreign-client ACE, and
        // the client has no FILE_CREATE_PIPE_INSTANCE right (0x00000004).
        let sddl = format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{service})\
             (A;;{CLIENT_PIPE_RIGHTS};;;{client})"
        );
        let mut desc = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(&sddl).as_ptr(),
                1,
                &mut desc,
                ptr::null_mut(),
            )
        } == 0
            || desc.is_null()
        {
            return Err("E_PIPE_DACL");
        }
        Ok(LocalMemory(desc))
    }
    fn serve(
        name: &str,
        service: &str,
        client: &str,
        attacker: &str,
        ready_path: &str,
    ) -> Result<()> {
        let pipe_name = pipe_name(name)?;
        let (service_sid, client_sid, attacker_sid) = (sid(service)?, sid(client)?, sid(attacker)?);
        if service_sid == client_sid || service_sid == attacker_sid || client_sid == attacker_sid {
            return Err("E_PIPE_IDENTITIES_NOT_DISTINCT");
        }
        if observe_process_sid().map_err(|_| "E_PIPE_SERVICE_TOKEN")? != service_sid {
            return Err("E_PIPE_SERVICE_IDENTITY");
        }
        let dacl = security_descriptor(service, client)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: dacl.0,
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                256,
                256,
                0,
                &attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err("E_PIPE_CREATE_EXCLUSIVE");
        }
        let pipe = Handle(handle);
        // Test-only event rendezvous: signal only after exclusive pipe creation.
        // The signal file lives in a service-owned, client-inaccessible directory.
        let _ready = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(ready_path)
            .map_err(|_| "E_PIPE_READY_SIGNAL")?;
        // A foreign SID is denied by the kernel's DACL and cannot reach
        // ConnectNamedPipe. The *one* eligible client must still pass an
        // independent kernel-issued impersonation-token identity check.
        let connected = unsafe { ConnectNamedPipe(pipe.0, ptr::null_mut()) };
        if connected == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            return Err("E_PIPE_CONNECT");
        }
        if read_one(pipe.0)? != b'R' {
            return Err("E_PIPE_REQUEST");
        }
        // The server owns this OS handle for the entire synchronous request.
        let borrowed = unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(pipe.0) };
        let observed =
            observe_client_sid_after_read(borrowed).map_err(|_| "E_PIPE_IMPERSONATION")?;
        if observed != client_sid || observed == attacker_sid {
            return Err("E_PIPE_PEER_IDENTITY_MISMATCH");
        }
        write_one(pipe.0, b'A')?;
        // Win32 disconnect discards unread bytes. Drain the reply before reuse.
        if unsafe { FlushFileBuffers(pipe.0) } == 0 {
            return Err("E_PIPE_REPLY_FLUSH");
        }
        if unsafe { DisconnectNamedPipe(pipe.0) } == 0 {
            return Err("E_PIPE_DISCONNECT");
        }
        eprintln!("T011_WINDOWS_SEPARATE_SID_PIPE_ACCEPTED_NONRELEASE");
        Ok(())
    }
    // Preserve the kernel verdict without exposing a pipe name, SID, token, or
    // unbounded operating-system text in public CI diagnostics.
    fn client_open_error(code: u32) -> &'static str {
        match code {
            ERROR_ACCESS_DENIED => "E_PIPE_CLIENT_OPEN_ACCESS_DENIED",
            ERROR_FILE_NOT_FOUND => "E_PIPE_CLIENT_OPEN_NOT_FOUND",
            ERROR_PIPE_BUSY => "E_PIPE_CLIENT_OPEN_BUSY",
            ERROR_INVALID_PARAMETER => "E_PIPE_CLIENT_OPEN_INVALID_PARAMETER",
            _ => "E_PIPE_CLIENT_OPEN_UNKNOWN",
        }
    }
    fn untrusted_open_is_kernel_denied(code: u32) -> bool {
        code == ERROR_ACCESS_DENIED
    }
    fn client(name: &str, expected_allowed: bool) -> Result<()> {
        let name = pipe_name(name)?;
        // The server fixture already signalled readiness using an OS event.
        // Do not allow a negative test to be reclassified as busy/missing.
        if expected_allowed && unsafe { WaitNamedPipeW(name.as_ptr(), 6000) } == 0 {
            return Err("E_PIPE_WAIT_EXPIRED");
        }
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                READ_WRITE_DATA,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            // Read the true kernel error immediately after failed CreateFileW.
            let code = unsafe { GetLastError() };
            if !expected_allowed && untrusted_open_is_kernel_denied(code) {
                eprintln!("T011_WINDOWS_UNTRUSTED_CLIENT_NO_GRANT");
                return Ok(());
            }
            return Err(client_open_error(code));
        }
        let pipe = Handle(handle);
        // The foreign client is forbidden from opening a pipe at all.
        // Even an unexpectedly successful open MUST fail the negative test.
        if !expected_allowed {
            return Err("E_PIPE_UNTRUSTED_CLIENT_CONNECTED");
        }
        write_one(pipe.0, b'R')?;
        if read_one(pipe.0)? != b'A' {
            return Err("E_PIPE_CLIENT_WRONG_DECISION");
        }
        eprintln!("T011_WINDOWS_LEGITIMATE_CLIENT_SID_OBSERVED");
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_PIPE_BUSY,
        };

        #[test]
        fn client_ace_allows_standard_read_write_metadata_but_never_create_instance() {
            // These are the documented standard file read/write access
            // bits EXCEPT the dangerous FILE_APPEND_DATA/CREATE_PIPE_INSTANCE.
            let rights = u32::from_str_radix(CLIENT_PIPE_RIGHTS.trim_start_matches("0x"), 16)
                .expect("literal SDDL access mask");
            assert_eq!(rights, 0x0012_019B);
            assert_eq!(
                rights & windows_sys::Win32::Storage::FileSystem::FILE_CREATE_PIPE_INSTANCE,
                0
            );
        }

        #[test]
        fn only_real_kernel_access_denial_counts_as_foreign_client_rejection() {
            assert!(untrusted_open_is_kernel_denied(ERROR_ACCESS_DENIED));
            assert!(!untrusted_open_is_kernel_denied(ERROR_FILE_NOT_FOUND));
            assert!(!untrusted_open_is_kernel_denied(ERROR_PIPE_BUSY));
            assert!(!untrusted_open_is_kernel_denied(ERROR_INVALID_PARAMETER));
            assert!(!untrusted_open_is_kernel_denied(0));
        }

        #[test]
        fn named_pipe_open_error_codes_are_distinct_and_fail_closed() {
            assert_eq!(
                client_open_error(ERROR_ACCESS_DENIED),
                "E_PIPE_CLIENT_OPEN_ACCESS_DENIED"
            );
            assert_eq!(
                client_open_error(ERROR_FILE_NOT_FOUND),
                "E_PIPE_CLIENT_OPEN_NOT_FOUND"
            );
            assert_eq!(
                client_open_error(ERROR_PIPE_BUSY),
                "E_PIPE_CLIENT_OPEN_BUSY"
            );
            assert_eq!(
                client_open_error(ERROR_INVALID_PARAMETER),
                "E_PIPE_CLIENT_OPEN_INVALID_PARAMETER"
            );
            assert_eq!(client_open_error(0xFFFF_FFFF), "E_PIPE_CLIENT_OPEN_UNKNOWN");
        }
    }
    pub fn main() -> std::process::ExitCode {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let result = match args.as_slice() {
            [mode, pipe, service, client_sid, attacker, ready_path] if mode == "serve" => {
                serve(pipe, service, client_sid, attacker, ready_path)
            }
            [mode, pipe] if mode == "allow" => client(pipe, true),
            [mode, pipe] if mode == "deny" => client(pipe, false),
            _ => Err("E_PIPE_ARGUMENTS"),
        };
        match result {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(code) => {
                eprintln!("{code}");
                std::process::ExitCode::FAILURE
            }
        }
    }
}
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    proof::main()
}
#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("E_PIPE_WINDOWS_ONLY");
    std::process::ExitCode::FAILURE
}
