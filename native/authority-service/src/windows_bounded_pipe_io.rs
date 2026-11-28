//! Shared nonshipping bounded overlapped I/O for native proof transports.
//! A pending OVERLAPPED is never released until the operation is drained.
use super::IdentityDenied;
use std::{
    os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_NO_DATA,
        ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    Storage::FileSystem::ReadFile,
    System::{
        Pipes::ConnectNamedPipe,
        Threading::{CreateEventW, WaitForSingleObject},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Progress {
    Bytes(usize),
    PendingTimeout,
    PendingTimeoutCancelled,
    PeerClosed,
}
pub(super) fn event() -> Result<OwnedHandle, IdentityDenied> {
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if raw.is_null() {
        return Err(IdentityDenied);
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
pub(super) fn deadline(timeout: Duration) -> Result<Instant, IdentityDenied> {
    if timeout < Duration::from_millis(1) || timeout > Duration::from_secs(30) {
        return Err(IdentityDenied);
    }
    Instant::now().checked_add(timeout).ok_or(IdentityDenied)
}
pub(super) fn remaining(end: Instant) -> Result<u32, IdentityDenied> {
    let millis = end
        .checked_duration_since(Instant::now())
        .ok_or(IdentityDenied)?
        .as_millis();
    if millis == 0 {
        return Err(IdentityDenied);
    }
    u32::try_from(millis).map_err(|_| IdentityDenied)
}
fn is_peer_close(error: u32) -> bool {
    matches!(
        error,
        ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
    )
}
// Once an overlapped operation is submitted, its storage must outlive it.
// Drain cancellation before returning; fail-stop this disposable proof
// on an unobservable completion, as in the existing disclosure primitive.
pub(super) fn finish(
    pipe: BorrowedHandle<'_>,
    ov: &mut OVERLAPPED,
    started: i32,
    millis: u32,
    on_failure: impl FnOnce(Progress),
) -> Result<usize, IdentityDenied> {
    if started == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            if is_peer_close(error) {
                on_failure(Progress::PeerClosed);
            }
            return Err(IdentityDenied);
        }
        let wait = unsafe { WaitForSingleObject(ov.hEvent, millis) };
        if wait != WAIT_OBJECT_0 {
            unsafe { CancelIoEx(pipe.as_raw_handle(), ov) };
            if unsafe { WaitForSingleObject(ov.hEvent, 5000) } != WAIT_OBJECT_0 {
                std::process::abort();
            }
            let mut discarded = 0;
            let completed =
                unsafe { GetOverlappedResult(pipe.as_raw_handle(), ov, &mut discarded, 0) };
            let error = if completed == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            if error == ERROR_IO_INCOMPLETE {
                std::process::abort();
            }
            if wait == WAIT_TIMEOUT {
                on_failure(if error == ERROR_OPERATION_ABORTED {
                    Progress::PendingTimeoutCancelled
                } else {
                    Progress::PendingTimeout
                });
            }
            return Err(IdentityDenied);
        }
    }
    let mut count = 0;
    if unsafe { GetOverlappedResult(pipe.as_raw_handle(), ov, &mut count, 0) } == 0 {
        let error = unsafe { GetLastError() };
        if error == ERROR_IO_INCOMPLETE {
            std::process::abort();
        }
        if is_peer_close(error) {
            on_failure(Progress::PeerClosed);
        }
        return Err(IdentityDenied);
    }
    Ok(count as usize)
}
pub(super) fn connect(pipe: BorrowedHandle<'_>, end: Instant) -> Result<(), IdentityDenied> {
    let event = event()?;
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = event.as_raw_handle();
    let millis = remaining(end)?;
    let started = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), &mut ov) };
    if started == 0 && unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
        return Ok(());
    }
    finish(pipe, &mut ov, started, millis, |_| {})?;
    Ok(())
}
pub(super) fn read_checked(
    pipe: BorrowedHandle<'_>,
    mut data: &mut [u8],
    end: Instant,
    progress: &mut impl FnMut(Progress),
    mut attest: impl FnMut() -> Result<(), IdentityDenied>,
) -> Result<(), IdentityDenied> {
    while !data.is_empty() {
        let event = event()?;
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = event.as_raw_handle();
        let millis = remaining(end)?;
        let capacity = data.len().min(16 * 1024);
        let started = unsafe {
            ReadFile(
                pipe.as_raw_handle(),
                data.as_mut_ptr(),
                capacity as u32,
                ptr::null_mut(),
                &mut ov,
            )
        };
        let count = finish(pipe, &mut ov, started, millis, &mut *progress)?;
        if count == 0 || count > capacity || Instant::now() >= end {
            return Err(IdentityDenied);
        }
        attest()?;
        if Instant::now() >= end {
            return Err(IdentityDenied);
        }
        progress(Progress::Bytes(count));
        data = &mut data[count..];
    }
    Ok(())
}
