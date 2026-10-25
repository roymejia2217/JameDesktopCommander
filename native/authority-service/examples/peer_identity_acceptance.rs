//! CI-only AF_UNIX peer test; NOT an IPC broker or a production endpoint.
//! Expected identity comes from the trusted disposable runner invocation.
//! Never interpret client bytes as authorization or a filesystem root.
#[cfg(target_os = "linux")]
mod linux {
    use jdc_authority_service::unix_accept::inspect_one_named_session;
    use jdc_authority_service::unix_peer::{
        inspect_peer_against_os_account, observe_connected_peer, KernelPeer,
    };
    use std::error::Error;
    use std::ffi::CString;
    use std::io::{self, Read, Write};
    use std::net::Shutdown;
    use std::os::fd::AsFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    // Compare kernel evidence inside the fixture; never serialize process
    // identifiers or account IDs into the CI log or the Bash verdict pipe.
    fn require_expected_peer(
        peer: &KernelPeer,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<(), &'static str> {
        if expected_uid == 0
            || expected_gid == 0
            || peer.uid() != expected_uid
            || peer.gid() != expected_gid
            || peer.pid() <= 0
            || peer.pid() == std::process::id() as i32
        {
            return Err("unexpected kernel peer identity");
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::fd::AsFd;

        #[test]
        fn same_process_socketpair_cannot_fake_an_independent_client() {
            let (client, server) = UnixStream::pair().expect("kernel stream");
            let actual = observe_connected_peer(server.as_fd()).expect("kernel credential");
            assert!(require_expected_peer(&actual, actual.uid(), actual.gid()).is_err());
            drop(client);
        }

        #[test]
        fn wrong_or_root_expected_credentials_are_never_accepted() {
            let (client, server) = UnixStream::pair().expect("kernel stream");
            let actual = observe_connected_peer(server.as_fd()).expect("kernel credential");
            assert!(require_expected_peer(&actual, 0, actual.gid()).is_err());
            assert!(require_expected_peer(&actual, actual.uid(), 0).is_err());
            assert!(
                require_expected_peer(&actual, actual.uid().wrapping_add(1), actual.gid()).is_err()
            );
            assert!(
                require_expected_peer(&actual, actual.uid(), actual.gid().wrapping_add(1)).is_err()
            );
            drop(client);
        }
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        let mut args = std::env::args().skip(1);
        let operation = args.next().ok_or("missing operation")?;
        let endpoint = args.next().ok_or("missing endpoint")?;
        let account_or_claim = args.next().ok_or("missing account or claim")?;
        let expected_uid_arg = args.next();
        let expected_gid_arg = args.next();
        if args.next().is_some() {
            return Err("unexpected argument".into());
        }

        match operation.as_str() {
            "serve" => {
                let expected_uid: u32 = expected_uid_arg.ok_or("missing expected UID")?.parse()?;
                let expected_gid: u32 = expected_gid_arg.ok_or("missing expected GID")?.parse()?;
                let expected = CString::new(account_or_claim)?;
                let listener = UnixListener::bind(&endpoint)?;
                println!("READY");
                io::stdout().flush()?;
                let (mut stream, _) = listener.accept()?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                let mut message_byte = [0u8; 1];
                stream.read_exact(&mut message_byte)?;
                let observed = observe_connected_peer(stream.as_fd())
                    .map_err(|_| io::Error::other("invalid kernel peer evidence"))?;
                require_expected_peer(&observed, expected_uid, expected_gid)?;
                let verdict =
                    if inspect_peer_against_os_account(stream.as_fd(), expected.as_c_str()).is_ok()
                    {
                        "MATCH"
                    } else {
                        "DENIED"
                    };
                // Verdict is deliberately non-sensitive; no kernel identity
                // or user-controlled payload reaches stdout or stderr.
                println!("OBSERVED_VERIFIED verdict={verdict}");
                io::stdout().flush()?;
                // Keep the coprocess pipe open until the harness acknowledges
                // the observed verdict; avoid relying on shell scheduling.
                let mut ack = [0u8; 1];
                io::stdin().read_exact(&mut ack)?;
                if ack != *b"K" {
                    return Err("invalid test acknowledgement".into());
                }
            }
            "client" => {
                if expected_uid_arg.is_some() || expected_gid_arg.is_some() {
                    return Err("unexpected client argument".into());
                }
                let mut stream = UnixStream::connect(&endpoint)?;
                // This is deliberately forged input. The server never parses it.
                stream.write_all(account_or_claim.as_bytes())?;
                println!("CONNECTED");
            }
            "serve-c4d" => {
                let expected_uid: u32 = expected_uid_arg.ok_or("missing expected UID")?.parse()?;
                let expected_gid: u32 = expected_gid_arg.ok_or("missing expected GID")?.parse()?;
                // The account_or_claim field is deliberately ignored: the
                // accepted principal comes only from this trusted invocation.
                let listener = UnixListener::bind(&endpoint)?;
                listener.set_nonblocking(true)?;
                println!("READY");
                io::stdout().flush()?;
                let verdict = if inspect_one_named_session(
                    &listener,
                    expected_uid,
                    expected_gid,
                    Duration::from_secs(4),
                )
                .is_ok()
                {
                    "ACCEPT"
                } else {
                    "DENIED"
                };
                println!("OBSERVED_C4D verdict={verdict}");
                io::stdout().flush()?;
                let mut ack = [0u8; 1];
                io::stdin().read_exact(&mut ack)?;
                if ack != *b"K" {
                    return Err("invalid C4d test acknowledgement".into());
                }
            }
            "client-c4d" | "client-c4d-invalid" => {
                if expected_uid_arg.is_some() || expected_gid_arg.is_some() {
                    return Err("unexpected C4d client argument".into());
                }
                // The caller-supplied 'claim:*' is not used as identity,
                // authorization, or part of the canonical request.
                let payload = br#"{"version":1,"kind":"create-directory","requestId":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","rootRef":"0123456789abcdef0123456789abcdef","relativePath":"safe"}"#;
                let mut stream = UnixStream::connect(&endpoint)?;
                if operation == "client-c4d-invalid" {
                    stream.write_all(b"\x00\x00\x00\x02[]")?;
                } else {
                    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
                    stream.write_all(payload)?;
                }
                stream.shutdown(Shutdown::Write)?;
                println!("CONNECTED");
            }
            _ => return Err("invalid operation".into()),
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("E_PEER_FIXTURE: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("E_PEER_LINUX_ONLY");
    std::process::exit(1);
}
