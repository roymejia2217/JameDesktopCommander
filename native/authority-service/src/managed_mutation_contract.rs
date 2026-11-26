//! Common nonshipping managed-object contract; admission remains separate.
pub(super) const MAX_BYTES: usize = 1024 * 1024;
pub(super) const STAGE: &str = ".jdc-stage";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MutationError {
    Denied,
    Collision,
    RecoveryRequired,
}

pub(super) enum Operation<'a> {
    Create { name: &'a str, bytes: &'a [u8] },
    Append { name: &'a str, bytes: &'a [u8] },
    Rewrite { name: &'a str, bytes: &'a [u8] },
    Rename { from: &'a str, to: &'a str },
}

// Deliberately narrow flat, portable experimental namespace. No streams,
// separator, private staging names, or DOS device aliases.
pub(super) fn valid_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 255
        || name.starts_with('.')
        || name.ends_with('.')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return false;
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
}

#[test]
fn portable_flat_names_deny_device_and_stream_aliases() {
    for rejected in [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        ".jdc-stage",
        "a:stream",
        "a.",
        "CON",
        "nul.txt",
        "COM1.bin",
        "LPT9",
    ] {
        assert!(!valid_name(rejected), "{rejected}");
    }
    assert!(valid_name("report-1_2.txt"));
}
