//! Test-only cross-runtime verification fixture; not a broker or service.
//! Converts hex-encoded C4d byte vectors from standard input into accept/deny.
use jdc_authority_service::canonical_request::validate_request_frame;
use std::io::{self, BufRead, Write};

fn nibble(input: u8) -> Option<u8> {
    match input {
        b'0'..=b'9' => Some(input - b'0'),
        b'a'..=b'f' => Some(input - b'a' + 10),
        _ => None,
    }
}
fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(2) || bytes.len() > 2 * (8192 + 4) * 2 {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}
fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let input = line?;
        let admitted = decode_hex(&input).is_some_and(|wire| validate_request_frame(&wire).is_ok());
        writeln!(output, "{}", if admitted { "accept" } else { "deny" })?;
    }
    output.flush()
}
