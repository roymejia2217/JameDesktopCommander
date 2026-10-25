//! Non-authorizing transport boundary for T011-C4d complete frames.
//! One connection permits exactly one complete frame followed by EOF.
//! This is NOT an IPC listener, canonical JSON validator, authenticated
//! peer, or a filesystem authority. Callers MUST set a finite OS read
//! deadline before passing any socket: Read alone cannot prevent stalls.
use std::io::Read;

/// Bound is identical to the version-one C4d TypeScript data contract.
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 8_192;
const HEADER_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameDenied;

/// Consume exactly one framed message; no buffered surplus or reuse.
/// The returned bytes still require strict canonical payload validation and
/// independently authenticated OS credentials before any privileged action.
pub fn read_one_frame<R: Read>(source: &mut R) -> Result<Vec<u8>, FrameDenied> {
    let mut header = [0_u8; HEADER_BYTES];
    source.read_exact(&mut header).map_err(|_| FrameDenied)?;
    let length = u32::from_be_bytes(header) as usize;
    if !(2..=MAX_FRAME_PAYLOAD_BYTES).contains(&length) {
        return Err(FrameDenied);
    }

    // One bounded allocation only, after validating the untrusted length.
    let mut frame = vec![0_u8; HEADER_BYTES + length];
    frame[..HEADER_BYTES].copy_from_slice(&header);
    source
        .read_exact(&mut frame[HEADER_BYTES..])
        .map_err(|_| FrameDenied)?;

    // C4d permits no second frame or trailing bytes. Production callers must
    // enforce EOF via write-half shutdown and a finite socket read deadline.
    let mut trailing = [0_u8; 1];
    match source.read(&mut trailing) {
        Ok(0) => Ok(frame),
        _ => Err(FrameDenied),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Read};

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    struct OneByte<'a> {
        remainder: &'a [u8],
    }

    impl Read for OneByte<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.remainder.is_empty() || out.is_empty() {
                return Ok(0);
            }
            out[0] = self.remainder[0];
            self.remainder = &self.remainder[1..];
            Ok(1)
        }
    }
    #[test]
    fn accepts_one_complete_frame_at_minimum_and_maximum_size() {
        for payload in [vec![b'{', b'}'], vec![b'a'; MAX_FRAME_PAYLOAD_BYTES]] {
            let original = framed(&payload);
            assert_eq!(
                read_one_frame(&mut Cursor::new(&original)),
                Ok(original),
                "valid bounded complete frames must survive unchanged"
            );
        }
    }

    #[test]
    fn reads_fragmented_input_without_requiring_single_kernel_read() {
        let wire = framed(br#"{"kind":"create-directory"}"#);
        assert_eq!(read_one_frame(&mut OneByte { remainder: &wire }), Ok(wire),);
    }

    #[test]
    fn denies_short_header_payload_and_disconnection() {
        let good = framed(br#"{"request":1}"#);
        for wire in [
            vec![],
            vec![0],
            vec![0, 0, 0],
            good[..4].to_vec(),
            good[..good.len() - 1].to_vec(),
        ] {
            assert_eq!(read_one_frame(&mut Cursor::new(wire)), Err(FrameDenied));
        }
    }
    #[test]
    fn rejects_zero_one_and_oversized_advertised_lengths_before_payload() {
        for length in [0_u32, 1_u32, 8193_u32, u32::MAX] {
            assert_eq!(
                read_one_frame(&mut Cursor::new(length.to_be_bytes())),
                Err(FrameDenied),
                "untrusted header must never allocate an oversized payload"
            );
        }
    }

    #[test]
    fn rejects_trailers_concatenated_frames_and_read_errors() {
        let first = framed(b"{}");
        let mut appended = first.clone();
        appended.push(0);
        assert_eq!(read_one_frame(&mut Cursor::new(appended)), Err(FrameDenied));
        let mut joined = first.clone();
        joined.extend_from_slice(&framed(b"{}"));
        assert_eq!(read_one_frame(&mut Cursor::new(joined)), Err(FrameDenied));
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "disconnected"))
            }
        }
        assert_eq!(read_one_frame(&mut Broken), Err(FrameDenied));
    }
}
