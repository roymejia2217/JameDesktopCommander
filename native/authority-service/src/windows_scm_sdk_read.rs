//! Disposable fixed-object SDK read. Not a general broker or storage grant.
use super::{
    attributes, bounded_io, descriptor, handoff_pipe::write_bytes_until, owned, role_sid,
    verify_security, Names, ProofPhase,
};
use jdc_authority_service::{
    policy_epoch::PolicyFence,
    windows_opened_read::read_opened_regular,
    windows_pipe_peer::{observe_client_sid_after_read, verify_live_issued_peer_after_read},
    windows_token::ScmFixtureRole,
    IdentityDenied,
};
use std::{
    cell::Cell,
    fs::{File, OpenOptions},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsHandle, AsRawHandle, BorrowedHandle, OwnedHandle},
    },
    path::PathBuf,
    ptr,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, PIPE_ACCESS_DUPLEX,
    },
    System::Pipes::{
        CreateNamedPipeW, PeekNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    },
};
// Existing native-peer mask: no FILE_CREATE_PIPE_INSTANCE / append grant.
// The actual Node duplex round trip and second-instance negative are tested.
const CLIENT_RIGHTS: u32 = 0x0012019B;
const SENTINEL: &[u8] = b"SERVICE_DOMAIN_BYTES";
const TIMEOUT: Duration = Duration::from_secs(8);
fn sentinel_path() -> Result<PathBuf, IdentityDenied> {
    let image = std::env::current_exe().map_err(|_| IdentityDenied)?;
    if image.file_name().and_then(|v| v.to_str()) != Some("jdc-authority-scm-issued-proof.exe") {
        return Err(IdentityDenied);
    }
    let stage = image.parent().ok_or(IdentityDenied)?;
    super::fixture_prefix(
        stage
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(IdentityDenied)?,
    )?;
    Ok(stage.join("authority-read").join("sentinel.bin"))
}
pub(super) fn verify_issuer_cannot_open_sentinel() -> Result<(), IdentityDenied> {
    match File::open(sentinel_path()?) {
        Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => Ok(()),
        _ => Err(IdentityDenied),
    }
}
fn pipe_name(names: &Names) -> Result<Vec<u16>, IdentityDenied> {
    let id = names
        .prefix
        .strip_prefix("Local\\JdcT011Job-")
        .ok_or(IdentityDenied)?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(IdentityDenied);
    }
    Ok(format!(r"\\.\pipe\JDC-T011-SCM-SDK-{id}")
        .encode_utf16()
        .chain(Some(0))
        .collect())
}
pub(super) struct SdkRead {
    pipe: OwnedHandle,
    file: File,
}
impl SdkRead {
    fn create_pipe(
        name: &[u16],
        sa: *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    ) -> Result<OwnedHandle, IdentityDenied> {
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                256,
                256,
                0,
                sa,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(IdentityDenied);
        }
        owned(raw)
    }
    pub(super) fn create(names: &Names) -> Result<Self, IdentityDenied> {
        let sd = descriptor(
            ScmFixtureRole::Authority,
            Some((ScmFixtureRole::Issuer, CLIENT_RIGHTS)),
            FILE_ALL_ACCESS,
        )?;
        let pipe = Self::create_pipe(&pipe_name(names)?, &attributes(&sd))?;
        verify_security(pipe.as_handle(), &role_sid(ScmFixtureRole::Authority)?, &sd)?;
        // Fixed administrator-staged object; never reopen a client-supplied path.
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(sentinel_path()?)
            .map_err(|_| IdentityDenied)?;
        Ok(Self { pipe, file })
    }
    pub(super) fn serve(
        self,
        child: BorrowedHandle<'_>,
        sid: &[u8],
        phase: &Cell<ProofPhase>,
        custody: impl Fn() -> Result<(), IdentityDenied>,
    ) -> Result<(), IdentityDenied> {
        if sid.is_empty() {
            return Err(IdentityDenied);
        }
        let end = bounded_io::deadline(TIMEOUT)?;
        let pipe = self.pipe.as_handle();
        phase.set(ProofPhase::SdkConnect);
        bounded_io::connect(pipe, end)?;
        phase.set(ProofPhase::SdkChallenge);
        custody()?;
        // The challenge is public. No file bytes before actual request authentication.
        write_bytes_until(&self.pipe, b"C", end)?;
        let attest = || {
            phase.set(ProofPhase::SdkConnector);
            custody()?;
            verify_live_issued_peer_after_read(pipe, child)?;
            phase.set(ProofPhase::SdkToken);
            if observe_client_sid_after_read(pipe)? != sid {
                return Err(IdentityDenied);
            }
            Ok(())
        };
        let mut request = [0u8; 1];
        phase.set(ProofPhase::SdkRequest);
        bounded_io::read_checked(
            pipe,
            &mut request,
            end,
            &mut |_| phase.set(ProofPhase::SdkRequest),
            attest,
        )?;
        phase.set(ProofPhase::SdkFrame);
        if request != *b"R" {
            return Err(IdentityDenied);
        }
        let mut pending = 0u32;
        if unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut pending,
                ptr::null_mut(),
            )
        } == 0
            || pending != 0
        {
            return Err(IdentityDenied);
        }
        let policy = PolicyFence::new(1).map_err(|_| IdentityDenied)?;
        let ticket = policy.issue_read().map_err(|_| IdentityDenied)?;
        policy
            .execute_once(&ticket, || {
                attest()?;
                phase.set(ProofPhase::SdkFile);
                let bytes = read_opened_regular(self.file).map_err(|_| IdentityDenied)?;
                if bytes != SENTINEL {
                    return Err(IdentityDenied);
                }
                attest()?;
                let mut frame = Vec::with_capacity(bytes.len() + 5);
                frame.push(b'A');
                frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                frame.extend_from_slice(&bytes);
                phase.set(ProofPhase::SdkReply);
                write_bytes_until(&self.pipe, &frame, end)
            })
            .map_err(|_| IdentityDenied)??;
        // Closing the server endpoint gives the SDK bounded EOF, as in the
        // existing local Windows issued-read proof. No unbounded pipe flush.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{descriptor_for_sids, sid_string};
    use super::*;
    use jdc_authority_service::{
        windows_issued_client::IssuedClient, windows_pipe_peer::observe_process_sid,
    };
    use std::{
        cell::Cell,
        ffi::OsStr,
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        Storage::FileSystem::SYNCHRONIZE,
        System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    };
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn sdk_client_mask_denies_actual_second_server_instance() {
        let sid = observe_process_sid().unwrap();
        let mut aligned = vec![0usize; sid.len().div_ceil(std::mem::size_of::<usize>())];
        unsafe {
            ptr::copy_nonoverlapping(sid.as_ptr(), aligned.as_mut_ptr().cast::<u8>(), sid.len())
        };
        let sid = sid_string(aligned.as_mut_ptr().cast()).unwrap();
        assert_ne!(sid, "S-1-5-18");
        let sd =
            descriptor_for_sids("S-1-0-0", Some((&sid, CLIENT_RIGHTS)), FILE_ALL_ACCESS).unwrap();
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name: Vec<u16> = format!(r"\\.\pipe\JDC-T011-SCM-SDK-{id:032x}")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let sa = attributes(&sd);
        let flags = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        let _first = owned(unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                flags,
                2,
                256,
                256,
                0,
                &sa,
            )
        })
        .unwrap();
        let second = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                flags,
                2,
                256,
                256,
                0,
                &sa,
            )
        };
        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if second != INVALID_HANDLE_VALUE {
            drop(owned(second).unwrap());
            panic!("SDK client mask admitted a second server instance");
        }
        assert_eq!(error, ERROR_ACCESS_DENIED);
    }
    // Explicit Node path and locked built runtime are required, just as in
    // the existing guarded-client integration tests. Same-token local proof,
    // never a substitute for the hosted SCM acceptance.
    #[test]
    #[ignore = "requires actual built Node/JDC SDK runtime"]
    fn real_jdc_sdk_fixed_read_and_wrong_connector_denial() {
        let node = PathBuf::from(std::env::var_os("JDC_T011_NODE_BINARY").unwrap());
        assert!(node.is_absolute() && node.is_file());
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../test/security/support/t011-windows-scm-sdk-client.mjs");
        assert!(script.is_file());
        let sid = observe_process_sid().unwrap();
        let mut aligned = vec![0usize; sid.len().div_ceil(std::mem::size_of::<usize>())];
        unsafe {
            ptr::copy_nonoverlapping(sid.as_ptr(), aligned.as_mut_ptr().cast::<u8>(), sid.len())
        };
        let sid_text = sid_string(aligned.as_mut_ptr().cast()).unwrap();
        let sd = descriptor_for_sids("S-1-0-0", Some((&sid_text, CLIENT_RIGHTS)), FILE_ALL_ACCESS)
            .unwrap();
        let system = std::env::var("SystemRoot").unwrap();
        for wrong in [false, true] {
            let id = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let temp = Temp(
                std::env::temp_dir().join(format!("jdc-scm-sdk-read-{}-{id}", std::process::id())),
            );
            std::fs::create_dir(&temp.0).unwrap();
            let sentinel = temp.0.join("sentinel.bin");
            std::fs::write(&sentinel, SENTINEL).unwrap();
            let file = File::open(&sentinel).unwrap();
            let name = format!(r"\\.\pipe\JDC-T011-SCM-SDK-{id:032x}");
            let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let pipe = SdkRead::create_pipe(&wide, &attributes(&sd)).unwrap();
            let server = SdkRead { pipe, file };
            let state = temp.0.to_str().unwrap();
            let command = format!("\"{}\" \"{}\" \"{name}\"", node.display(), script.display());
            let mut child = IssuedClient::launch_suspended(
                &node,
                OsStr::new(&command),
                &[
                    ("SystemRoot", &system),
                    ("USERPROFILE", state),
                    ("HOME", state),
                    ("TEMP", state),
                    ("TMP", state),
                    ("DESKTOP_COMMANDER_CONFIG_DIR", state),
                    ("DESKTOP_COMMANDER_DISABLE_TELEMETRY", "1"),
                    ("DC_FLAG_URL", "http://127.0.0.1:9/"),
                ],
            )
            .unwrap();
            let other = owned(unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                    0,
                    std::process::id(),
                )
            })
            .unwrap();
            child.resume().unwrap();
            let expected = if wrong {
                other.as_handle()
            } else {
                child.process_handle()
            };
            let calls = Cell::new(0usize);
            let phase = Cell::new(ProofPhase::ObserverInitial);
            let result = server.serve(expected, &sid, &phase, || {
                calls.set(calls.get() + 1);
                Ok(())
            });
            child.wait_for_exit(Duration::from_secs(10)).unwrap();
            if wrong {
                // Second custody check is after an actual SDK request byte.
                assert_eq!(calls.get(), 2);
                assert_eq!(phase.get(), ProofPhase::SdkConnector);
                assert!(result.is_err());
                assert_eq!(child.exit_code().unwrap(), 1);
            } else {
                assert!(
                    result.is_ok(),
                    "actual fixed SDK read failed after {} custody checks",
                    calls.get()
                );
                assert_eq!(child.exit_code().unwrap(), 19);
            }
        }
    }
}
