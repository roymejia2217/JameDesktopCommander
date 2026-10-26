//! T011-C4d data-shape verification only. Never authorizes a caller.
use crate::frame_reader::FrameDenied;
use serde::{Deserialize, Serialize};

const MAX_BYTES: usize = 8_192;
const MAX_PATH_BYTES: usize = 4_096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    kind: String,
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "expectedEpoch")]
    expected_epoch: String,
    #[serde(rename = "rootRef")]
    root_ref: String,
    #[serde(rename = "relativePath")]
    relative_path: String,
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}
fn uuid_v4(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, &b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            14 => b == b'4',
            19 => (b'8'..=b'b').contains(&b),
            _ => lower_hex(b),
        })
}

fn epoch(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.starts_with(|c: char| ('1'..='9').contains(&c))
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u64>().is_ok()
}

fn reserved_device(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    // CONIN$ and CONOUT$ are special Win32 console device handles too.
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let mut chars = upper.chars();
    match (
        chars.next(),
        chars.next(),
        chars.next(),
        chars.next(),
        chars.next(),
    ) {
        (Some('C'), Some('O'), Some('M'), Some(n), None)
        | (Some('L'), Some('P'), Some('T'), Some(n), None) => {
            ('1'..='9').contains(&n) || matches!(n, '¹' | '²' | '³')
        }
        _ => false,
    }
}

/// Shared path grammar for both C4d decoding and OS-rooted operations.
/// A decoded path must never be rejected solely by a second, divergent parser.
pub(crate) fn safe_relative_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return false;
    }
    let parts: Vec<_> = path.split('/').collect();
    parts.len() <= 64
        && parts.into_iter().all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.len() <= 255
                && !segment.ends_with(['.', ' '])
                && !reserved_device(segment)
                && !segment.chars().any(|c| {
                    c <= '\u{001f}'
                        || c == '\u{007f}'
                        || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
                })
        })
}

/// Canonical protocol data only, NOT proof of caller or filesystem authority.
/// All fields are immutable after decoding; they must still be compared against
/// an independently OS-protected, revocable policy by the future broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalCreateDirectory {
    request_id: String,
    expected_epoch: u64,
    root_ref: String,
    relative_path: String,
}

impl CanonicalCreateDirectory {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn expected_epoch(&self) -> u64 {
        self.expected_epoch
    }
    pub fn root_ref(&self) -> &str {
        &self.root_ref
    }
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
}

/// Compatibility contract: syntax acceptance alone never grants authority.
pub fn validate_request_frame(frame: &[u8]) -> Result<(), FrameDenied> {
    decode_create_directory_frame(frame).map(|_| ())
}

/// Decode one canonical v1 frame into immutable protocol data, not a grant.
/// The OS-authenticated broker and handle-based dispatcher do not exist yet.
pub fn decode_create_directory_frame(
    frame: &[u8],
) -> Result<CanonicalCreateDirectory, FrameDenied> {
    if frame.len() < 6 || frame.len() > MAX_BYTES + 4 {
        return Err(FrameDenied);
    }
    let length = u32::from_be_bytes(frame[0..4].try_into().map_err(|_| FrameDenied)?) as usize;
    if !(2..=MAX_BYTES).contains(&length) || length != frame.len() - 4 {
        return Err(FrameDenied);
    }
    let json = &frame[4..];
    let req: Request = serde_json::from_slice(json).map_err(|_| FrameDenied)?;
    if serde_json::to_vec(&req)
        .map_err(|_| FrameDenied)?
        .as_slice()
        != json
        || req.version != 1
        || req.kind != "create-directory"
        || !uuid_v4(&req.request_id)
        || !epoch(&req.expected_epoch)
        || req.root_ref.len() != 32
        || !req.root_ref.bytes().all(lower_hex)
        || !safe_relative_path(&req.relative_path)
    {
        return Err(FrameDenied);
    }
    Ok(CanonicalCreateDirectory {
        request_id: req.request_id,
        expected_epoch: req.expected_epoch.parse::<u64>().map_err(|_| FrameDenied)?,
        root_ref: req.root_ref,
        relative_path: req.relative_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "11111111-1111-4111-8111-111111111111";
    const ROOT: &str = "0123456789abcdef0123456789abcdef";
    fn payload(path: &str) -> String {
        format!(
            r#"{{"version":1,"kind":"create-directory","requestId":"{ID}","expectedEpoch":"18446744073709551615","rootRef":"{ROOT}","relativePath":"{path}"}}"#
        )
    }
    fn frame(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }
    #[test]
    fn decoded_request_preserves_all_canonical_fields_without_policy_grant() {
        let wire = frame(payload("project/nuevo").as_bytes());
        let parsed = decode_create_directory_frame(&wire).expect("valid canonical request");
        assert_eq!(parsed.request_id(), ID);
        assert_eq!(parsed.expected_epoch(), u64::MAX);
        assert_eq!(parsed.root_ref(), ROOT);
        assert_eq!(parsed.relative_path(), "project/nuevo");
        assert_eq!(validate_request_frame(&wire), Ok(()));
    }

    #[test]
    fn typed_decoder_rejects_uncanonical_or_unauthorized_request_shapes() {
        let original = payload("safe");
        for raw in [
            original.replace("create-directory", "read"),
            original.replace("18446744073709551615", "0"),
            payload("../outside"),
            payload("NUL.txt"),
            format!("{original} "),
        ] {
            assert_eq!(
                decode_create_directory_frame(&frame(raw.as_bytes())),
                Err(FrameDenied),
                "accepted malformed request: {raw}"
            );
        }
    }

    #[test]
    fn accepts_exact_c4d_canonical_request_without_granting_authority() {
        let valid = frame(payload("project/nuevo").as_bytes());
        assert_eq!(validate_request_frame(&valid), Ok(()));
    }
    #[test]
    fn rejects_mismatched_length_and_noncanonical_field_encodings() {
        let original = payload("project/nuevo");
        let wrong = [
            format!(" {original}"),
            format!("{original}\n"),
            original.replace("\"version\":1", "\"version\":1.0"),
            original.replace("\"version\":1", "\"version\":1,\"version\":1"),
            original.replace("\"kind\"", "\"\\u006bind\""),
            original.replace("\"kind\"", "\"unexpected\":7,\"kind\""),
        ];
        for raw in wrong {
            assert_eq!(
                validate_request_frame(&frame(raw.as_bytes())),
                Err(FrameDenied),
                "{raw}"
            );
        }
        let mut length = frame(original.as_bytes());
        length[3] = length[3].wrapping_add(1);
        assert_eq!(validate_request_frame(&length), Err(FrameDenied));
    }
    #[test]
    fn valid_unicode_request_is_data_not_authorization() {
        let raw = payload("科研/archivo");
        assert_eq!(validate_request_frame(&frame(raw.as_bytes())), Ok(()));
    }

    #[test]
    fn denies_bad_uuid_root_version_and_epoch_forms() {
        let original = payload("ok");
        let altered = [
            original.replace(ID, "11111111-1111-5111-8111-111111111111"),
            original.replace(ID, "11111111-1111-4111-7111-111111111111"),
            original.replace(ID, "11111111-1111-4111-8111-11111111111A"),
            original.replace(ROOT, "ABCDEF0123456789ABCDEF0123456789"),
            original.replace(ROOT, "C:/Users/Public"),
            original.replace("\"version\":1", "\"version\":2"),
            original.replace("18446744073709551615", "0"),
            original.replace("18446744073709551615", "01"),
            original.replace("18446744073709551615", "2e1"),
        ];
        for raw in altered {
            assert_eq!(
                validate_request_frame(&frame(raw.as_bytes())),
                Err(FrameDenied),
                "{raw}"
            );
        }
    }

    #[test]
    fn denies_oversized_and_device_alias_paths() {
        for path in [
            "a".repeat(256),
            "a".repeat(4097),
            format!("{}z", "a/".repeat(65)),
            String::from("a/./b"),
            String::from("com1.log"),
            String::from("LPT².doc"),
            String::from("CONIN$"),
            String::from("CONOUT$.txt"),
            String::from("a/"),
        ] {
            let raw = payload(&path);
            assert_eq!(
                validate_request_frame(&frame(raw.as_bytes())),
                Err(FrameDenied)
            );
        }
        let mut huge = frame(b"{}");
        huge[0..4].copy_from_slice(&8193_u32.to_be_bytes());
        assert_eq!(validate_request_frame(&huge), Err(FrameDenied));
        assert_eq!(
            validate_request_frame(&[0xff, 0xff, 0xff, 0xff]),
            Err(FrameDenied)
        );
    }

    #[test]
    fn rejects_unsafe_relative_paths_and_invalid_epoch() {
        for bad in [
            "a/../b",
            "C:/disk",
            "a\\b",
            "a//b",
            "CON",
            "con.txt",
            "LPT¹.log",
            "trailing.",
            "trailing ",
            "a:b",
            "a?b",
        ] {
            let json = payload(bad);
            assert_eq!(
                validate_request_frame(&frame(json.as_bytes())),
                Err(FrameDenied),
                "{bad}"
            );
        }
        let stale = payload("ok").replace("18446744073709551615", "18446744073709551616");
        assert_eq!(
            validate_request_frame(&frame(stale.as_bytes())),
            Err(FrameDenied)
        );
    }
}
