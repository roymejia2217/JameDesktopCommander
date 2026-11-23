//! Bounded native response to one already-authenticated Windows pipe peer.
//! This does not open a filesystem path, grant a root, or authenticate IPC.
//! The trusted broker must supply an OVERLAPPED-mode pipe it created itself.
//! Timeout may disclose a prefix; callers MUST discard/close the channel.
use crate::IdentityDenied;
use std::{
    os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_IO_PENDING, WAIT_OBJECT_0},
    Storage::FileSystem::WriteFile,
    System::{
        Threading::{CreateEventW, WaitForSingleObject},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};
const CHUNK: usize = 16 * 1024;
const MAX_PAYLOAD: usize = 1024 * 1024;
const MAX_DEADLINE_MS: u128 = 30_000;

/// Write an exact byte slice on the caller-owned, connected overlapped pipe.
/// Uses a single event wait per pending chunk: no poll loop or unbounded
/// per-operation deadline. The caller must close any pipe after an error.
fn write_chunk(pipe: BorrowedHandle<'_>, chunk: &[u8], millis: u32) -> Result<(), IdentityDenied> {
    let raw_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if raw_event.is_null() {
        return Err(IdentityDenied);
    }
    let event = unsafe { OwnedHandle::from_raw_handle(raw_event) };
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = event.as_raw_handle();
    let raw_pipe = pipe.as_raw_handle();
    let started = unsafe {
        WriteFile(
            raw_pipe,
            chunk.as_ptr().cast(),
            chunk.len() as u32,
            ptr::null_mut(),
            &mut ov,
        )
    };
    if started == 0 {
        if unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(IdentityDenied);
        }
        if unsafe { WaitForSingleObject(event.as_raw_handle(), millis) } != WAIT_OBJECT_0 {
            unsafe { CancelIoEx(raw_pipe, &ov) };
            // Windows explicitly forbids dropping OVERLAPPED while pending.
            // Failure to observe completion after cancellation must fail-stop
            // this non-shipping broker rather than corrupt a reused stack.
            if unsafe { WaitForSingleObject(event.as_raw_handle(), 5_000) } != WAIT_OBJECT_0 {
                std::process::abort();
            }
            let mut drained = 0;
            unsafe { GetOverlappedResult(raw_pipe, &ov, &mut drained, 0) };
            return Err(IdentityDenied);
        }
    }
    let mut written = 0;
    if unsafe { GetOverlappedResult(raw_pipe, &ov, &mut written, 0) } == 0
        || written != chunk.len() as u32
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

/// Send only one complete, size-bounded native read response framing:
/// 'A' || u32 big-endian length || exact file object bytes.
///
/// No ownable bytes are returned to the caller. This method does not ensure
/// the peer consumed bytes, cannot undo an already-sent prefix on timeout,
/// and MUST only be called while the policy epoch read lock is held.
pub(crate) fn disclose_bounded(
    pipe: BorrowedHandle<'_>,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), IdentityDenied> {
    if bytes.len() > MAX_PAYLOAD || timeout.is_zero() || timeout.as_millis() > MAX_DEADLINE_MS {
        return Err(IdentityDenied);
    }
    let mut frame = Vec::with_capacity(5 + bytes.len());
    frame.push(b'A');
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    let start = Instant::now();
    for chunk in frame.chunks(CHUNK) {
        let remaining = timeout.checked_sub(start.elapsed()).ok_or(IdentityDenied)?;
        let milliseconds = u32::try_from(remaining.as_millis()).map_err(|_| IdentityDenied)?;
        if milliseconds == 0 {
            return Err(IdentityDenied);
        }
        write_chunk(pipe, chunk, milliseconds)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsHandle;

    #[test]
    fn invalid_time_bounds_and_oversized_payload_never_start_a_write() {
        let raw_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        assert!(!raw_event.is_null());
        let event = unsafe { OwnedHandle::from_raw_handle(raw_event) };
        for timeout in [Duration::ZERO, Duration::from_secs(31)] {
            assert!(disclose_bounded(event.as_handle(), b"not-authorized", timeout).is_err());
        }
        assert!(disclose_bounded(
            event.as_handle(),
            &vec![0x81; MAX_PAYLOAD + 1],
            Duration::from_secs(1),
        )
        .is_err());
    }

    #[test]
    fn wrong_kernel_handle_type_cannot_be_used_as_an_output_channel() {
        let raw_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        assert!(!raw_event.is_null());
        let event = unsafe { OwnedHandle::from_raw_handle(raw_event) };
        assert!(disclose_bounded(
            event.as_handle(),
            &[0, 255, 129, 42],
            Duration::from_secs(1),
        )
        .is_err());
    }
}

#[cfg(test)]
mod stalled_peer_tests {
    use super::*;
    use std::{
        ffi::OsStr,
        os::windows::{ffi::OsStrExt, io::AsHandle},
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, ReadFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
            OPEN_EXISTING, PIPE_ACCESS_OUTBOUND,
        },
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_BYTE, PIPE_WAIT,
        },
    };

    #[test]
    fn connected_peer_that_never_reads_must_exhaust_one_absolute_response_deadline() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!(
            r"\\.\pipe\JDC-BOUNDED-NATIVE-{}-{unique}",
            std::process::id()
        );
        let name: Vec<u16> = OsStr::new(&name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                ptr::null(),
            )
        };
        assert_ne!(
            raw, INVALID_HANDLE_VALUE,
            "real overlapped named pipe required"
        );
        let server = unsafe { OwnedHandle::from_raw_handle(raw) };
        let client_raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                0x80000000,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        assert_ne!(
            client_raw, INVALID_HANDLE_VALUE,
            "real connected read-only peer required"
        );
        let _client = unsafe { OwnedHandle::from_raw_handle(client_raw) };
        let event_raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        assert!(!event_raw.is_null());
        let event = unsafe { OwnedHandle::from_raw_handle(event_raw) };
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = event.as_raw_handle();
        let connected = unsafe { ConnectNamedPipe(server.as_raw_handle(), &mut ov) };
        assert!(
            connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED,
            "named pipe peer must be genuinely connected before testing stalled reads"
        );
        // Prove that the kernel pipe really transmits bytes before testing
        // the peer's refusal to consume any further data.
        let probe = b"REAL_PIPE";
        assert_eq!(
            disclose_bounded(server.as_handle(), probe, Duration::from_secs(1)),
            Ok(())
        );
        let mut observed = vec![0u8; 5 + probe.len()];
        let mut count = 0u32;
        assert_ne!(
            unsafe {
                ReadFile(
                    _client.as_raw_handle(),
                    observed.as_mut_ptr().cast(),
                    observed.len() as u32,
                    &mut count,
                    ptr::null_mut(),
                )
            },
            0,
            "real pipe peer must read the genuine probe frame"
        );
        assert_eq!(count as usize, observed.len());
        assert_eq!(&observed[..5], &[b'A', 0, 0, 0, probe.len() as u8]);
        assert_eq!(&observed[5..], probe);
        let begin = Instant::now();
        let result = disclose_bounded(
            server.as_handle(),
            &vec![0x5a; MAX_PAYLOAD],
            Duration::from_millis(200),
        );
        assert_eq!(
            result,
            Err(IdentityDenied),
            "the absent reader must never accept a full bounded response"
        );
        assert!(
            begin.elapsed() >= Duration::from_millis(50),
            "the test must reach a genuinely pending write, not an immediate invalid-handle denial"
        );
        assert!(
            begin.elapsed() < Duration::from_secs(6),
            "cancellation may not leave an unbounded Win32 pipe write in-flight"
        );
    }
}
