//! CI-only AF_UNIX peer test; NOT an IPC broker or a production endpoint.
//! Expected identity comes from the trusted disposable runner invocation.
//! Never interpret client bytes as authorization or a filesystem root.
#[cfg(target_os = "linux")]
mod linux {
    use jdc_authority_service::unix_peer::{
        inspect_peer_against_os_account, observe_connected_peer,
    };
    use std::error::Error;
    use std::ffi::CString;
    use std::io::{self, Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    pub fn run() -> Result<(), Box<dyn Error>> {
        let mut args = std::env::args().skip(1);
        let operation = args.next().ok_or("missing operation")?;
        let endpoint = args.next().ok_or("missing endpoint")?;
        let account_or_claim = args.next().ok_or("missing account or claim")?;
        if args.next().is_some() {
            return Err("unexpected argument".into());
        }

        match operation.as_str() {
            "serve" => {
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
                let verdict =
                    if inspect_peer_against_os_account(stream.as_fd(), expected.as_c_str()).is_ok()
                    {
                        "MATCH"
                    } else {
                        "DENIED"
                    };
                println!(
                    "OBSERVED uid={} gid={} pid={} verdict={verdict}",
                    observed.uid(),
                    observed.gid(),
                    observed.pid()
                );
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
                let mut stream = UnixStream::connect(&endpoint)?;
                // This is deliberately forged input. The server never parses it.
                stream.write_all(account_or_claim.as_bytes())?;
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
