//! Disposable SCM handoff IPC; no broker permissions or data operations.
//! The issuer sends one bounded canonical handoff directly. The authority
//! authenticates the actual pinned SCM connector and last writer's token.
use super::{attributes, descriptor, owned, role_sid, verify_security, Handoff, Names, ProofPhase};
use jdc_authority_service::{
    windows_pipe_peer::{observe_client_sid_after_read, verify_live_issued_peer_after_read},
    windows_token::ScmFixtureRole,
    IdentityDenied,
};
use std::cell::Cell;
use std::{
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, OwnedHandle},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        CreateFileW, WriteFile, FILE_ALL_ACCESS, FILE_FLAG_FIRST_PIPE_INSTANCE,
        FILE_FLAG_OVERLAPPED, FILE_WRITE_DATA, OPEN_EXISTING, PIPE_ACCESS_INBOUND, READ_CONTROL,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, SYNCHRONIZE,
    },
    System::{
        Pipes::{
            CreateNamedPipeW, PeekNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        IO::OVERLAPPED,
    },
};
#[path = "windows_bounded_pipe_io.rs"]
mod bounded_io;
const LIMIT: usize = 128;
const CLIENT_RIGHTS: u32 = FILE_WRITE_DATA | READ_CONTROL | SYNCHRONIZE;
const TIMEOUT: Duration = Duration::from_secs(5);
fn name(names: &Names) -> Result<Vec<u16>, IdentityDenied> {
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
    Ok(format!(r"\\.\pipe\JDC-T011-SCM-HANDOFF-{id}")
        .encode_utf16()
        .chain(Some(0))
        .collect())
}
fn client(name: &[u16]) -> Result<OwnedHandle, IdentityDenied> {
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            CLIENT_RIGHTS,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(IdentityDenied);
    }
    owned(raw)
}
fn write_bytes(client: &OwnedHandle, bytes: &[u8]) -> Result<(), IdentityDenied> {
    if bytes.is_empty() || bytes.len() > LIMIT + 4 {
        return Err(IdentityDenied);
    }
    let end = bounded_io::deadline(TIMEOUT)?;
    let event = bounded_io::event()?;
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = event.as_raw_handle();
    let millis = bounded_io::remaining(end)?;
    let started = unsafe {
        WriteFile(
            client.as_raw_handle(),
            bytes.as_ptr(),
            bytes.len() as u32,
            ptr::null_mut(),
            &mut ov,
        )
    };
    if bounded_io::finish(client.as_handle(), &mut ov, started, millis, |_| {})? != bytes.len() {
        return Err(IdentityDenied);
    }
    Ok(())
}
fn write_frame(client: &OwnedHandle, bytes: &[u8]) -> Result<(), IdentityDenied> {
    if bytes.is_empty() || bytes.len() > LIMIT {
        return Err(IdentityDenied);
    }
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    write_bytes(client, &frame)
}
pub(super) fn send(
    names: &Names,
    handoff: Handoff,
    phase: &Cell<ProofPhase>,
) -> Result<OwnedHandle, IdentityDenied> {
    phase.set(ProofPhase::IssuerPipeOpen);
    // Only the fixed SCM issuer is allowed to reach this call site.
    let expected = descriptor(
        ScmFixtureRole::Authority,
        Some((ScmFixtureRole::Issuer, CLIENT_RIGHTS)),
        FILE_ALL_ACCESS,
    )?;
    let client = client(&name(names)?)?;
    phase.set(ProofPhase::IssuerPipeDescriptor);
    verify_security(
        client.as_handle(),
        &role_sid(ScmFixtureRole::Authority)?,
        &expected,
    )?;
    phase.set(ProofPhase::IssuerPipeWrite);
    write_frame(&client, handoff.encode().as_bytes())?;
    Ok(client)
}
pub(super) struct HandoffPipe(OwnedHandle);
impl HandoffPipe {
    fn create_raw(
        name: &[u16],
        sa: *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    ) -> Result<Self, IdentityDenied> {
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                0,
                256,
                0,
                sa,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(IdentityDenied);
        }
        Ok(Self(owned(raw)?))
    }
    pub(super) fn create(names: &Names, phase: &Cell<ProofPhase>) -> Result<Self, IdentityDenied> {
        phase.set(ProofPhase::ObserverPipeCreate);
        let sd = descriptor(
            ScmFixtureRole::Authority,
            Some((ScmFixtureRole::Issuer, CLIENT_RIGHTS)),
            FILE_ALL_ACCESS,
        )?;
        let pipe = Self::create_raw(&name(names)?, &attributes(&sd))?;
        phase.set(ProofPhase::ObserverPipeDescriptor);
        verify_security(
            pipe.0.as_handle(),
            &role_sid(ScmFixtureRole::Authority)?,
            &sd,
        )?;
        Ok(pipe)
    }
    #[cfg(test)]
    fn receive(self, issuer: BorrowedHandle<'_>, sid: &[u8]) -> Result<Handoff, IdentityDenied> {
        self.receive_traced(issuer, sid, &Cell::new(ProofPhase::ObserverInitial))
    }
    pub(super) fn receive_traced(
        self,
        issuer: BorrowedHandle<'_>,
        sid: &[u8],
        phase: &Cell<ProofPhase>,
    ) -> Result<Handoff, IdentityDenied> {
        self.receive_until(issuer, sid, bounded_io::deadline(TIMEOUT)?, phase)
    }
    fn receive_until(
        self,
        issuer: BorrowedHandle<'_>,
        sid: &[u8],
        end: Instant,
        phase: &Cell<ProofPhase>,
    ) -> Result<Handoff, IdentityDenied> {
        phase.set(ProofPhase::ObserverConnect);
        if sid.is_empty() {
            return Err(IdentityDenied);
        }
        let pipe = self.0.as_handle();
        bounded_io::connect(pipe, end).inspect_err(|_| eprintln!("E_SCM_HANDOFF_CONNECT"))?;
        let attest = || {
            phase.set(ProofPhase::ObserverConnector);
            verify_live_issued_peer_after_read(pipe, issuer)
                .inspect_err(|_| eprintln!("E_SCM_HANDOFF_CONNECTOR"))?;
            phase.set(ProofPhase::ObserverToken);
            let observed = observe_client_sid_after_read(pipe)
                .inspect_err(|_| eprintln!("E_SCM_HANDOFF_TOKEN"))?;
            phase.set(ProofPhase::ObserverPeerSid);
            if observed != sid {
                eprintln!("E_SCM_HANDOFF_SID");
                return Err(IdentityDenied);
            }
            Ok(())
        };
        let mut header = [0u8; 4];
        phase.set(ProofPhase::ObserverHeader);
        bounded_io::read_checked(
            pipe,
            &mut header,
            end,
            &mut |_| phase.set(ProofPhase::ObserverHeader),
            attest,
        )
        .inspect_err(|_| eprintln!("E_SCM_HANDOFF_HEADER"))?;
        phase.set(ProofPhase::ObserverFrame);
        let length = u32::from_be_bytes(header) as usize;
        if !(1..=LIMIT).contains(&length) {
            return Err(IdentityDenied);
        }
        let mut payload = vec![0u8; length];
        phase.set(ProofPhase::ObserverBody);
        bounded_io::read_checked(
            pipe,
            &mut payload,
            end,
            &mut |_| phase.set(ProofPhase::ObserverBody),
            attest,
        )
        .inspect_err(|_| eprintln!("E_SCM_HANDOFF_BODY"))?;
        phase.set(ProofPhase::ObserverFrame);
        let mut extra = 0u32;
        if unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut extra,
                ptr::null_mut(),
            )
        } == 0
            || extra != 0
        {
            eprintln!("E_SCM_HANDOFF_EXTRA_OR_PEEK");
            return Err(IdentityDenied);
        }
        let handoff = Handoff::parse(std::str::from_utf8(&payload).map_err(|_| IdentityDenied)?)
            .inspect_err(|_| eprintln!("E_SCM_HANDOFF_RECORD"))?;
        handoff
            .issuer
            .verify(issuer)
            .inspect_err(|_| eprintln!("E_SCM_HANDOFF_STAMP"))?;
        Ok(handoff)
    }
    #[cfg(test)]
    fn local_test(name: &[u16]) -> Result<Self, IdentityDenied> {
        Self::create_raw(name, ptr::null())
    }
}
#[cfg(test)]
mod tests {
    use super::super::Stamp;
    use super::*;
    use jdc_authority_service::windows_pipe_peer::observe_process_sid;
    use std::time::{SystemTime, UNIX_EPOCH};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    fn current_pin() -> OwnedHandle {
        owned(unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                0,
                std::process::id(),
            )
        })
        .unwrap()
    }
    fn unique_name() -> Vec<u16> {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            r"\\.\pipe\JDC-T011-SCM-HANDOFF-{}-{suffix}",
            std::process::id()
        )
        .encode_utf16()
        .chain(Some(0))
        .collect()
    }
    fn handoff(issuer: Stamp) -> Handoff {
        Handoff {
            issuer,
            child: Stamp {
                pid: issuer.pid.checked_add(1).unwrap(),
                creation: issuer.creation,
            },
            thread: 1,
        }
    }
    fn send_frame(name: &[u16], bytes: &[u8]) -> Result<OwnedHandle, IdentityDenied> {
        let client = client(name)?;
        write_frame(&client, bytes)?;
        Ok(client)
    }
    #[test]
    fn hosted_failure_phase_preserves_the_actual_identity_denial() {
        let pin = current_pin();
        let expected = handoff(Stamp::capture(pin.as_handle()).unwrap());
        let mut sid = observe_process_sid().unwrap();
        *sid.last_mut().unwrap() ^= 1;
        let name = unique_name();
        let server = HandoffPipe::local_test(&name).unwrap();
        let _client = send_frame(&name, expected.encode().as_bytes()).unwrap();
        let phase = Cell::new(ProofPhase::ObserverInitial);
        assert!(server
            .receive_traced(pin.as_handle(), &sid, &phase)
            .is_err());
        assert_eq!(phase.get(), ProofPhase::ObserverPeerSid);
        assert_eq!(phase.get().code(), 28);
    }
    #[test]
    fn real_handoff_requires_live_connector_and_exact_frame() {
        let name = unique_name();
        let server = HandoffPipe::local_test(&name).unwrap();
        assert!(HandoffPipe::local_test(&name).is_err());
        let pin = current_pin();
        let current = pin.as_handle();
        let handoff = handoff(Stamp::capture(current).unwrap());
        let _client = send_frame(&name, handoff.encode().as_bytes()).unwrap();
        let sid = observe_process_sid().unwrap();
        let actual = server.receive(current, &sid).unwrap();
        assert_eq!(actual.encode(), handoff.encode());
    }
    #[test]
    fn protected_pipe_descriptor_is_observable_at_both_endpoints() {
        use super::super::{descriptor_for_sids, sid_string, Local};
        use windows_sys::Win32::{
            Security::{
                Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT},
                OWNER_SECURITY_INFORMATION,
            },
            System::JobObjects::CreateJobObjectW,
        };
        // Local owner comes from the kernel, not a declared SID. This checks
        // real NPFS descriptor semantics, not the distinct SCM role proof.
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
        let _sd = Local(raw);
        let owner = sid_string(owner).unwrap();
        let expected =
            descriptor_for_sids(&owner, Some(("S-1-0-0", CLIENT_RIGHTS)), FILE_ALL_ACCESS).unwrap();
        let name = unique_name();
        let server = HandoffPipe::create_raw(&name, &attributes(&expected)).unwrap();
        verify_security(server.0.as_handle(), &owner, &expected).unwrap();
        let client = client(&name).unwrap();
        verify_security(client.as_handle(), &owner, &expected).unwrap();
        let pin = current_pin();
        let expected_frame = handoff(Stamp::capture(pin.as_handle()).unwrap());
        write_frame(&client, expected_frame.encode().as_bytes()).unwrap();
        assert_eq!(
            server
                .receive(pin.as_handle(), &observe_process_sid().unwrap())
                .unwrap()
                .encode(),
            expected_frame.encode()
        );
    }
    #[test]
    fn real_handoff_denies_a_different_live_process_with_the_same_sid() {
        use jdc_authority_service::windows_issued_client::IssuedClient;
        use std::ffi::OsStr;
        let image = std::env::current_exe().unwrap();
        let command = format!("\"{}\"", image.display());
        let system = std::env::var("SystemRoot").unwrap();
        let other = IssuedClient::launch_suspended(
            &image,
            OsStr::new(&command),
            &[("SystemRoot", &system)],
        )
        .unwrap();
        let pin = current_pin();
        let current = pin.as_handle();
        let expected = handoff(Stamp::capture(current).unwrap());
        let sid = observe_process_sid().unwrap();
        let name = unique_name();
        let server = HandoffPipe::local_test(&name).unwrap();
        let _client = send_frame(&name, expected.encode().as_bytes()).unwrap();
        assert!(server.receive(other.process_handle(), &sid).is_err());
        assert!(Stamp::capture(other.process_handle()).is_ok());
    }
    #[test]
    fn real_handoff_rejects_stalled_peer_under_one_deadline() {
        let pin = current_pin();
        let sid = observe_process_sid().unwrap();
        let name = unique_name();
        let server = HandoffPipe::local_test(&name).unwrap();
        let _client = client(&name).unwrap();
        let start = Instant::now();
        let end = bounded_io::deadline(Duration::from_millis(200)).unwrap();
        assert!(server
            .receive_until(
                pin.as_handle(),
                &sid,
                end,
                &Cell::new(ProofPhase::ObserverInitial)
            )
            .is_err());
        assert!(start.elapsed() >= Duration::from_millis(50));
        assert!(start.elapsed() < Duration::from_secs(6));
    }
    #[test]
    fn real_handoff_denies_wrong_token_and_malformed_frame() {
        let pin = current_pin();
        let current = pin.as_handle();
        let expected = handoff(Stamp::capture(current).unwrap());
        let sid = observe_process_sid().unwrap();
        let mut wrong_sid = sid.clone();
        *wrong_sid.last_mut().unwrap() ^= 1;
        let name = unique_name();
        let server = HandoffPipe::local_test(&name).unwrap();
        let _client = send_frame(&name, expected.encode().as_bytes()).unwrap();
        assert!(server.receive(current, &wrong_sid).is_err());
        let name = unique_name();
        let server = HandoffPipe::local_test(&name).unwrap();
        let mut bad = expected.encode().into_bytes();
        bad.push(b'X');
        let _client = send_frame(&name, &bad).unwrap();
        assert!(server.receive(current, &sid).is_err());
        let name = unique_name();
        let server = HandoffPipe::local_test(&name).unwrap();
        let oversized_client = client(&name).unwrap();
        write_bytes(&oversized_client, &((LIMIT + 1) as u32).to_be_bytes()).unwrap();
        assert!(server.receive(current, &sid).is_err());
        let name = unique_name();
        let server = HandoffPipe::local_test(&name).unwrap();
        let client = client(&name).unwrap();
        let bytes = expected.encode().into_bytes();
        let mut extra = (bytes.len() as u32).to_be_bytes().to_vec();
        extra.extend_from_slice(&bytes);
        extra.push(b'X');
        write_bytes(&client, &extra).unwrap();
        assert!(server.receive(current, &sid).is_err());
    }
}
