//! Internal C4d handle-only directory creation slice, **not a broker**.
//! There is no pathname bootstrap, IPC exposure or authorization in this module.
//! The caller must supply an OS-attested, already-open directory capability.
use cap_std::fs::Dir;
use std::io;

use crate::canonical_request::safe_relative_path;

/// Holds only a supplied directory capability, never an ambient root path.
/// Construction is not policy authentication. Do not expose this type to IPC
/// until the OS-protected policy owner and peer have been verified.
pub struct RootedDirectory {
    root: Dir,
}

fn validate_single_child(name: &str) -> io::Result<()> {
    // Never use a second character policy. The protocol grammar is the only
    // source of truth; explicitly require exactly one component here.
    if !safe_relative_path(name) || name.contains('/') {
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

    /// Create a nested directory strictly relative to the supplied root handle.
    /// This has NO IPC or policy authorization and cannot be a release operation.
    /// Validate the whole input before mutation, then retain an opened handle at
    /// each level instead of rebuilding a pathname or following an ambient path.
    pub fn create_descendant(&self, relative: &str) -> io::Result<()> {
        // Validate the *complete* path before any mutation. This is exactly
        // the same bound, segment grammar and reserved-name set as C4d.
        if !safe_relative_path(relative) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "E_PATH_DENIED",
            ));
        }
        let mut child: Option<Dir> = None;
        for component in relative.split('/') {
            let parent = child.as_ref().unwrap_or(&self.root);
            match parent.create_dir(component) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
            child = Some(parent.open_dir(component)?);
        }
        Ok(())
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
    fn unicode_single_child_and_nested_child_share_canonical_protocol_grammar() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let sentinel = outside.join("sentinel");
        std::fs::write(&sentinel, b"UNCHANGED").unwrap();
        let dir = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&root, ambient_authority()).unwrap(),
        );
        dir.create_child("résumé").unwrap();
        dir.open_child("résumé")
            .unwrap()
            .create_child("资料")
            .unwrap();
        dir.create_descendant("科研/mi carpeta").unwrap();
        assert!(root.join("résumé/资料").is_dir());
        assert!(root.join("科研/mi carpeta").is_dir());
        assert!(!outside.join("科研").exists());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"UNCHANGED");
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
            "CONIN$",
            "CONOUT$.log",
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

    #[test]
    fn creates_nested_directories_from_preopened_root_and_is_idempotent() {
        let fixture = tempfile::tempdir().unwrap();
        let inside = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&inside).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let dir = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&inside, ambient_authority()).unwrap(),
        );
        assert!(dir.create_descendant("alpha/beta/gamma").is_ok());
        assert!(dir.create_descendant("alpha/beta/gamma").is_ok());
        assert!(inside.join("alpha/beta/gamma").is_dir());
        assert!(!outside.join("alpha").exists());
    }

    #[test]
    fn existing_nondirectory_component_is_denied_without_file_replacement() {
        let fixture = tempfile::tempdir().unwrap();
        let inside = fixture.path().join("allowed");
        std::fs::create_dir(&inside).unwrap();
        let sentinel = inside.join("existing_file");
        std::fs::write(&sentinel, b"PRESERVE_THIS_FILE").unwrap();
        let dir = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&inside, ambient_authority()).unwrap(),
        );
        assert!(dir.create_descendant("existing_file/child").is_err());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"PRESERVE_THIS_FILE");
    }

    #[test]
    fn invalid_later_component_denies_without_partial_creation() {
        let fixture = tempfile::tempdir().unwrap();
        let inside = fixture.path().join("allowed");
        std::fs::create_dir(&inside).unwrap();
        let dir = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&inside, ambient_authority()).unwrap(),
        );
        for bad in [
            "fresh/../outside",
            "fresh//child",
            "fresh/NUL.txt",
            "fresh/CONIN$",
            "fresh/CONOUT$.txt",
            "fresh/a.",
            "fresh/COM1",
            "fresh/LPT².log",
            "fresh/child\\outside",
            "fresh/",
        ] {
            assert!(dir.create_descendant(bad).is_err(), "accepted {bad:?}");
            assert!(
                !inside.join("fresh").exists(),
                "partial mutation for {bad:?}"
            );
        }
        let deep = "a/".repeat(65) + "z";
        assert!(dir.create_descendant(&deep).is_err());
        assert!(!inside.join("a").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nested_mkdir_denies_outside_symlink_without_outside_mutation() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let inside = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&inside).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"OUTSIDE_ORIGINAL").unwrap();
        symlink(&outside, inside.join("alias")).unwrap();
        let dir = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&inside, ambient_authority()).unwrap(),
        );
        assert!(dir.create_descendant("alias/forbidden").is_err());
        assert!(!outside.join("forbidden").exists());
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"OUTSIDE_ORIGINAL"
        );
    }

    #[cfg(windows)]
    #[test]
    fn nested_mkdir_denies_ntfs_junction_escape_with_real_os_fixture() {
        use std::process::Command;
        let fixture = tempfile::tempdir().unwrap();
        let inside = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&inside).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"OUTSIDE_ORIGINAL").unwrap();
        let link = inside.join("alias");
        let output = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .expect("official Windows cmd.exe junction fixture");
        assert!(
            output.status.success(),
            "junction setup failed: status={:?}, stdout={:?}, stderr={:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(link.is_dir(), "junction fixture must resolve");
        let dir = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&inside, ambient_authority()).unwrap(),
        );
        assert!(dir.create_descendant("alias/forbidden").is_err());
        assert!(!outside.join("forbidden").exists());
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"OUTSIDE_ORIGINAL"
        );
    }
}
