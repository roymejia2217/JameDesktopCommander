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
            CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE,
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
    const CLIENT_PIPE_RIGHTS: &str = "0x00100003"; // synchronize + read/write, no create-instance
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
    fn security_descriptor(service: &str, client: &str, attacker: &str) -> Result<LocalMemory> {
        // An explicit protected DACL. No Everyone/Anonymous ACE, and no
        // FILE_CREATE_PIPE_INSTANCE for either test client.
        let sddl = format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{service})\
             (A;;{CLIENT_PIPE_RIGHTS};;;{client})\
             (A;;{CLIENT_PIPE_RIGHTS};;;{attacker})"
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
    fn serve(name: &str, service: &str, client: &str, attacker: &str) -> Result<()> {
        let pipe_name = pipe_name(name)?;
        let (service_sid, client_sid, attacker_sid) = (sid(service)?, sid(client)?, sid(attacker)?);
        if service_sid == client_sid || service_sid == attacker_sid || client_sid == attacker_sid {
            return Err("E_PIPE_IDENTITIES_NOT_DISTINCT");
        }
        if observe_process_sid().map_err(|_| "E_PIPE_SERVICE_TOKEN")? != service_sid {
            return Err("E_PIPE_SERVICE_IDENTITY");
        }
        let dacl = security_descriptor(service, client, attacker)?;
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
        for expected_allowed in [false, true] {
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
            let allowed = observed == client_sid;
            if allowed != expected_allowed {
                return Err("E_PIPE_PEER_IDENTITY_MISMATCH");
            }
            if !allowed && observed != attacker_sid {
                return Err("E_PIPE_UNEXPECTED_FOREIGN_IDENTITY");
            }
            write_one(pipe.0, if allowed { b'A' } else { b'D' })?;
            // Win32 disconnect discards unread bytes. Drain the reply before reuse.
            if unsafe { FlushFileBuffers(pipe.0) } == 0 {
                return Err("E_PIPE_REPLY_FLUSH");
            }
            if unsafe { DisconnectNamedPipe(pipe.0) } == 0 {
                return Err("E_PIPE_DISCONNECT");
            }
            if !allowed {
                eprintln!("T011_WINDOWS_FOREIGN_SID_DENIED");
            }
        }
        eprintln!("T011_WINDOWS_SEPARATE_SID_PIPE_ACCEPTED_NONRELEASE");
        Ok(())
    }
    fn client(name: &str, expected_allowed: bool) -> Result<()> {
        let name = pipe_name(name)?;
        if unsafe { WaitNamedPipeW(name.as_ptr(), 6000) } == 0 {
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
            return Err("E_PIPE_CLIENT_OPEN");
        }
        let pipe = Handle(handle);
        write_one(pipe.0, b'R')?;
        let observed = read_one(pipe.0)?;
        if observed != if expected_allowed { b'A' } else { b'D' } {
            return Err("E_PIPE_CLIENT_WRONG_DECISION");
        }
        eprintln!(
            "{}",
            if expected_allowed {
                "T011_WINDOWS_LEGITIMATE_CLIENT_SID_OBSERVED"
            } else {
                "T011_WINDOWS_UNTRUSTED_CLIENT_NO_GRANT"
            }
        );
        Ok(())
    }
    pub fn main() -> std::process::ExitCode {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let result = match args.as_slice() {
            [mode, pipe, service, client_sid, attacker] if mode == "serve" => {
                serve(pipe, service, client_sid, attacker)
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
