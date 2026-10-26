//! Internal C4d handle-only directory creation slice, **not a broker**.
//! There is no pathname bootstrap, IPC exposure or authorization in this module.
//! The caller must supply an OS-attested, already-open directory capability.
use cap_std::fs::Dir;
use std::io;

/// Holds only a supplied directory capability, never an ambient root path.
/// Construction is not policy authentication. Do not expose this type to IPC
/// until the OS-protected policy owner and peer have been verified.
pub struct RootedDirectory {
    root: Dir,
}

fn validate_single_child(name: &str) -> io::Result<()> {
    // Portable and intentionally narrow: one path component, ASCII only,
    // no Windows device aliases or names with trailing dot/space.
    let valid = !name.is_empty()
        && name.len() <= 100
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.'
        })
        && !name.ends_with('.');
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0');
    if !valid || reserved {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "E_CHILD_NAME_DENIED",
        ));
    }
    Ok(())
}

impl RootedDirectory {
    /// Only a trusted bootstrap may supply the already-open and policy-pinned
    /// directory. This constructor does no filesystem name lookup.
    pub fn from_preopened(root: Dir) -> Self {
        Self { root }
    }

    /// Atomic OS-relative single-child mkdir. The supplied handle remains
    /// anchored even if the root's original pathname changes independently.
    pub fn create_child(&self, name: &str) -> io::Result<()> {
        validate_single_child(name)?;
        self.root.create_dir(name)
    }

    /// Open only a validated, single-component child directory via cap-std.
    /// The returned child remains anchored to its opened directory handle.
    /// Neither this function nor its parent constructor grants policy authority.
    pub fn open_child(&self, name: &str) -> io::Result<Self> {
        validate_single_child(name)?;
        self.root.open_dir(name).map(Self::from_preopened)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::ambient_authority;

    #[test]
    fn legitimate_single_child_creation_is_relative_to_the_opened_root() {
        let fixture = tempfile::tempdir().unwrap();
        let root_path = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let marker = outside.join("sentinel");
        std::fs::write(&marker, b"ORIGINAL_OUTSIDE_BYTES").unwrap();
        let preopened = Dir::open_ambient_dir(&root_path, ambient_authority()).unwrap();
        let capability = RootedDirectory::from_preopened(preopened);
        assert!(capability.create_child("genuine_child").is_ok());
        assert!(root_path.join("genuine_child").is_dir());
        assert!(!outside.join("genuine_child").exists());
        assert_eq!(std::fs::read(&marker).unwrap(), b"ORIGINAL_OUTSIDE_BYTES");
    }

    #[test]
    fn malformed_and_traversing_names_must_never_create_outside() {
        let fixture = tempfile::tempdir().unwrap();
        let root_path = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let marker = outside.join("sentinel");
        std::fs::write(&marker, b"KEEP_OUTSIDE_UNCHANGED").unwrap();
        let preopened = Dir::open_ambient_dir(&root_path, ambient_authority()).unwrap();
        let capability = RootedDirectory::from_preopened(preopened);
        for name in [
            "",
            ".",
            "..",
            "../outside/hijacked",
            "/absolute",
            "nested/child",
            r"..\outside\hijacked",
            r"C:\temp",
            "NUL",
            "NUL.txt",
            "CON",
            "LPT1",
            "COM1",
            "trailing.",
            "trailing ",
            "abc:stream",
        ] {
            assert!(
                capability.create_child(name).is_err(),
                "unsafe name accepted: {name:?}"
            );
        }
        assert!(!outside.join("hijacked").exists());
        assert_eq!(std::fs::read(&marker).unwrap(), b"KEEP_OUTSIDE_UNCHANGED");
    }

    #[test]
    fn operation_never_silently_succeeds_for_an_existing_entry() {
        let fixture = tempfile::tempdir().unwrap();
        let preopened = Dir::open_ambient_dir(fixture.path(), ambient_authority()).unwrap();
        let capability = RootedDirectory::from_preopened(preopened);
        assert!(capability.create_child("only_once").is_ok());
        assert!(capability.create_child("only_once").is_err());
    }

    #[test]
    fn nested_directory_open_must_preserve_handle_relative_authority() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("allowed");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::create_dir_all(root.join("sibling")).unwrap();
        let preopened = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
        let parent = RootedDirectory::from_preopened(preopened);
        let nested = parent.open_child("nested").unwrap();
        nested.create_child("grandchild").unwrap();
        assert!(root.join("nested/grandchild").is_dir());
        assert!(!root.join("sibling/grandchild").exists());
        for rejected in [
            "",
            ".",
            "..",
            "../sibling",
            "nested/grandchild",
            r"C:\escape",
            "NUL.txt",
        ] {
            assert!(parent.open_child(rejected).is_err(), "opened {rejected:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nested_open_must_reject_symlink_escape_and_preserve_outside_bytes() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let sentinel = outside.join("sentinel");
        std::fs::write(&sentinel, b"UNTOUCHED_OUTSIDE").unwrap();
        symlink(&outside, root.join("outside_alias")).unwrap();
        let preopened = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
        let parent = RootedDirectory::from_preopened(preopened);
        assert!(parent.open_child("outside_alias").is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"UNTOUCHED_OUTSIDE");
        assert!(!outside.join("grandchild").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn opened_child_remains_anchored_after_name_replacement_by_outside_symlink() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let marker = outside.join("sentinel");
        std::fs::write(&marker, b"ORIGINAL_OUTSIDE").unwrap();
        let parent = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&root, ambient_authority()).unwrap(),
        );
        let opened_child = parent.open_child("nested").unwrap();
        std::fs::rename(root.join("nested"), root.join("moved")).unwrap();
        symlink(&outside, root.join("nested")).unwrap();
        opened_child.create_child("safe").unwrap();
        assert!(root.join("moved/safe").is_dir());
        assert!(!outside.join("safe").exists());
        assert_eq!(std::fs::read(&marker).unwrap(), b"ORIGINAL_OUTSIDE");
    }
}
