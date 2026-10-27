//! Internal C4d handle-only directory creation slice, **not a broker**.
//! There is no pathname bootstrap, IPC exposure or authorization in this module.
//! The caller must supply an OS-attested, already-open directory capability.
use cap_std::fs::{Dir, OpenOptions};
use std::io::{self, Write};

use crate::canonical_request::safe_relative_path;

/// Holds only a supplied directory capability, never an ambient root path.
/// Construction is not policy authentication. Do not expose this type to IPC
/// until the OS-protected policy owner and peer have been verified.
pub struct RootedDirectory {
    root: Dir,
}

/// Separate, service-owned staging directory capability. Only a protected
/// bootstrap may construct this value: there is intentionally no public
/// path-based constructor or way to fabricate it from untrusted MCP input.
/// Tests construct private fixtures to exercise the OS rename primitive.
///
/// External callers cannot turn an arbitrary ambient path into staging:
/// ```compile_fail
/// use jdc_authority_service::handle_mkdir::ProtectedStagingDirectory;
/// use cap_std::{ambient_authority, fs::Dir};
/// let stage = ProtectedStagingDirectory {
///     root: Dir::open_ambient_dir(".", ambient_authority()).unwrap(),
/// };
/// ```
pub struct ProtectedStagingDirectory {
    root: Dir,
}

impl ProtectedStagingDirectory {
    /// Windows bootstrap consumes a preopened directory handle; the OS token,
    /// protected DACL and service SID are checked before accepting it.
    /// Caller must independently pin the expected state-root object identity.
    #[cfg(windows)]
    pub fn from_preopened_service_state(
        preopened: std::fs::File,
    ) -> Result<Self, crate::IdentityDenied> {
        let observed = crate::windows_policy_root::observe_preopened_service_state(preopened)?;
        Ok(Self::from_verified_windows_state(observed))
    }

    /// Linux bootstrap accepts only the independently provisioned absolute
    /// systemd state directory, observed as pinned, non-symlink OS handles.
    /// Still NO validated policy bytes, grants or complete service lifecycle.
    #[cfg(target_os = "linux")]
    pub fn from_provisioned_linux_state() -> Result<Self, crate::IdentityDenied> {
        let observed = crate::linux_policy_root::observe_provisioned_directory()?;
        Ok(Self::from_verified_linux_state(observed))
    }

    /// Conversion only, NOT authorization: OS owner/DACL and service identity
    /// must already have been checked by the state observer on this same handle.
    /// No caller-controlled pathname is reopened.
    #[cfg(windows)]
    pub(crate) fn from_verified_windows_state(
        observed: crate::windows_policy_root::ObservedWindowsStateDirectory,
    ) -> Self {
        Self {
            root: Dir::from_std_file(observed.into_verified_file()),
        }
    }

    /// Linux uses the already verified O_PATH directory fd as an openat root.
    /// No path traversal, symlink resolution or ambient reopen is performed.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_verified_linux_state(
        observed: crate::linux_policy_root::ObservedPolicyDirectory,
    ) -> Self {
        Self {
            root: Dir::from(observed.into_verified_fd()),
        }
    }
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

    /// Strict create-only, bounded data write under an already-open root.
    /// Never opens or truncates existing files, including external hardlink
    /// aliases; no ambient paths or symlink-following path revalidation.
    /// Not atomic visibility and not an authenticated/published broker API.
    pub fn create_new_file(&self, relative: &str, bytes: &[u8]) -> io::Result<()> {
        const MAX_CREATE_BYTES: usize = 1024 * 1024;
        if !safe_relative_path(relative) || bytes.len() > MAX_CREATE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "E_NEW_FILE_DENIED",
            ));
        }
        let mut components = relative.split('/').peekable();
        let mut opened: Option<Dir> = None;
        while let Some(component) = components.next() {
            let parent = opened.as_ref().unwrap_or(&self.root);
            if components.peek().is_some() {
                let child = parent.open_dir(component)?;
                opened = Some(child);
            } else {
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                let mut file = parent.open_with(component, &options)?;
                file.write_all(bytes)?;
                file.sync_all()?;
            }
        }
        Ok(())
    }

    /// Experimental **replace-by-new-inode** semantics. Never opens the old
    /// final inode for writing, which matters for cross-root hardlink aliases.
    /// A future broker must prove separate-principal staging custody, same-volume
    /// rename, destination state under races and crash recovery. In particular,
    /// the destination might disappear between metadata and rename; this is NOT
    /// yet an atomic compare-and-replace contract. There is no MCP grant here.
    pub fn replace_existing_file_staged(
        &self,
        staging: &ProtectedStagingDirectory,
        relative: &str,
        stage_nonce: &str,
        bytes: &[u8],
    ) -> io::Result<()> {
        const MAX_BYTES: usize = 1024 * 1024;
        let valid_nonce = stage_nonce.len() == 32
            && stage_nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !safe_relative_path(relative) || !valid_nonce || bytes.len() > MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "E_REPLACE_DENIED",
            ));
        }
        let mut pieces = relative.split('/').peekable();
        let mut opened: Option<Dir> = None;
        while pieces.peek().is_some() {
            let component = pieces.next().expect("nonempty canonical path");
            let parent = opened.as_ref().unwrap_or(&self.root);
            if pieces.peek().is_none() {
                // Require a previously existing regular file. A final hardlink
                // is an entry, not permission to mutate its shared inode.
                if !parent.symlink_metadata(component)?.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "E_REPLACE_NONREGULAR",
                    ));
                }
                let stage = format!(".jdc-stage-{stage_nonce}");
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                let mut fresh = staging.root.open_with(&stage, &options)?;
                if let Err(err) = fresh.write_all(bytes).and_then(|_| fresh.sync_all()) {
                    drop(fresh);
                    let _ = staging.root.remove_file(&stage);
                    return Err(err);
                }
                drop(fresh);
                let replaced = staging.root.rename(&stage, parent, component);
                if replaced.is_err() {
                    let _ = staging.root.remove_file(&stage);
                }
                return replaced;
            }
            opened = Some(parent.open_dir(component)?);
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "E_REPLACE_DENIED",
        ))
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
    fn replace_existing_hardlink_alias_must_preserve_outside_inode_bytes() {
        let fixture = tempfile::tempdir().unwrap();
        let allowed = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&allowed).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let victim = outside.join("victim.bin");
        let previous = b"EXTERNAL_BYTES_MUST_REMAIN_UNTOUCHED";
        std::fs::write(&victim, previous).unwrap();
        std::fs::hard_link(&victim, allowed.join("alias.bin"))
            .expect("genuine same-volume hardlink, not a mock");
        let stage_dir = fixture.path().join("protected-staging");
        std::fs::create_dir(&stage_dir).unwrap();
        let staging = ProtectedStagingDirectory {
            root: Dir::open_ambient_dir(&stage_dir, ambient_authority()).unwrap(),
        };
        let rooted = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&allowed, ambient_authority()).unwrap(),
        );
        rooted
            .replace_existing_file_staged(
                &staging,
                "alias.bin",
                "0123456789abcdef0123456789abcdef",
                b"AUTHORIZED_NEW_CONTENT",
            )
            .expect("protected handle-relative replacement must work on both supported OSes");
        assert_eq!(std::fs::read(&victim).unwrap(), previous);
        assert_eq!(
            std::fs::read(allowed.join("alias.bin")).unwrap(),
            b"AUTHORIZED_NEW_CONTENT"
        );
    }

    #[test]
    fn staged_replacement_must_not_use_attacker_writable_destination_directory() {
        let fixture = tempfile::tempdir().unwrap();
        let allowed = fixture.path().join("allowed");
        let private_stage = fixture.path().join("protected-staging");
        let outside = fixture.path().join("outside");
        for folder in [&allowed, &private_stage, &outside] {
            std::fs::create_dir(folder).unwrap();
        }
        let victim = outside.join("victim.bin");
        let protected_bytes = b"ORIGINAL_EXTERNAL_CONTENT";
        std::fs::write(&victim, protected_bytes).unwrap();
        std::fs::hard_link(&victim, allowed.join("target.bin")).unwrap();
        // A hostile client occupies the same predictable temporary basename in
        // the *untrusted allowed tree*. A correct implementation never opens it.
        let nonce = "0123456789abcdef0123456789abcdef";
        let hostile_stage = allowed.join(format!(".jdc-stage-{nonce}"));
        std::fs::hard_link(&victim, &hostile_stage).unwrap();
        let rooted = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&allowed, ambient_authority()).unwrap(),
        );
        let staging = ProtectedStagingDirectory {
            root: Dir::open_ambient_dir(&private_stage, ambient_authority()).unwrap(),
        };
        rooted
            .replace_existing_file_staged(&staging, "target.bin", nonce, b"NEW_IN_ROOT")
            .expect("private stage must be independent of destination namespace");
        assert_eq!(std::fs::read(&victim).unwrap(), protected_bytes);
        assert_eq!(std::fs::read(&hostile_stage).unwrap(), protected_bytes);
        assert_eq!(
            std::fs::read(allowed.join("target.bin")).unwrap(),
            b"NEW_IN_ROOT"
        );
        assert_eq!(std::fs::read_dir(&private_stage).unwrap().count(), 0);
    }

    #[test]
    fn staged_replacement_refuses_occupied_protected_nonce_without_side_effects() {
        let fixture = tempfile::tempdir().unwrap();
        let allowed = fixture.path().join("allowed");
        let stage_dir = fixture.path().join("protected-stage");
        std::fs::create_dir(&allowed).unwrap();
        std::fs::create_dir(&stage_dir).unwrap();
        std::fs::write(allowed.join("file.bin"), b"ORIGINAL").unwrap();
        let nonce = "abcdef0123456789abcdef0123456789";
        let temp_name = stage_dir.join(format!(".jdc-stage-{nonce}"));
        std::fs::write(&temp_name, b"KEEP_STAGING").unwrap();
        let rooted = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&allowed, ambient_authority()).unwrap(),
        );
        let staging = ProtectedStagingDirectory {
            root: Dir::open_ambient_dir(&stage_dir, ambient_authority()).unwrap(),
        };
        assert!(rooted
            .replace_existing_file_staged(&staging, "file.bin", nonce, b"WRONG",)
            .is_err());
        assert_eq!(
            std::fs::read(allowed.join("file.bin")).unwrap(),
            b"ORIGINAL"
        );
        assert_eq!(std::fs::read(&temp_name).unwrap(), b"KEEP_STAGING");
    }

    #[cfg(windows)]
    #[test]
    fn staged_replacement_denies_intermediate_ntfs_junction_to_outside() {
        use std::process::Command;
        let fixture = tempfile::tempdir().unwrap();
        let allowed = fixture.path().join("allowed");
        let stage_dir = fixture.path().join("protected-stage");
        let outside = fixture.path().join("outside");
        for folder in [&allowed, &stage_dir, &outside] {
            std::fs::create_dir(folder).unwrap();
        }
        let victim = outside.join("file.bin");
        std::fs::write(&victim, b"NEVER_MODIFY").unwrap();
        let alias = allowed.join("junction");
        let status = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&alias)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "fixture must create real junction: {status:?}"
        );
        let rooted = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&allowed, ambient_authority()).unwrap(),
        );
        let staging = ProtectedStagingDirectory {
            root: Dir::open_ambient_dir(&stage_dir, ambient_authority()).unwrap(),
        };
        assert!(rooted
            .replace_existing_file_staged(
                &staging,
                "junction/file.bin",
                "0123456789abcdef0123456789abcdef",
                b"ATTEMPT"
            )
            .is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"NEVER_MODIFY");
        assert_eq!(std::fs::read_dir(&stage_dir).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staged_replacement_denies_intermediate_symlink_to_outside() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let allowed = fixture.path().join("allowed");
        let stage_dir = fixture.path().join("protected-stage");
        let outside = fixture.path().join("outside");
        for folder in [&allowed, &stage_dir, &outside] {
            std::fs::create_dir(folder).unwrap();
        }
        let victim = outside.join("file.bin");
        std::fs::write(&victim, b"NEVER_MODIFY").unwrap();
        symlink(&outside, allowed.join("alias")).unwrap();
        let rooted = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&allowed, ambient_authority()).unwrap(),
        );
        let staging = ProtectedStagingDirectory {
            root: Dir::open_ambient_dir(&stage_dir, ambient_authority()).unwrap(),
        };
        assert!(rooted
            .replace_existing_file_staged(
                &staging,
                "alias/file.bin",
                "0123456789abcdef0123456789abcdef",
                b"ATTEMPT"
            )
            .is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"NEVER_MODIFY");
        assert_eq!(std::fs::read_dir(&stage_dir).unwrap().count(), 0);
    }

    #[test]
    fn replace_existing_hardlink_alias_rejects_invalid_staging_identity() {
        let fixture = tempfile::tempdir().unwrap();
        let allowed = fixture.path().join("allowed");
        std::fs::create_dir(&allowed).unwrap();
        std::fs::write(allowed.join("file.bin"), b"SAFE").unwrap();
        let stage_dir = fixture.path().join("protected-staging");
        std::fs::create_dir(&stage_dir).unwrap();
        let staging = ProtectedStagingDirectory {
            root: Dir::open_ambient_dir(&stage_dir, ambient_authority()).unwrap(),
        };
        let rooted = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&allowed, ambient_authority()).unwrap(),
        );
        for invalid in [
            "",
            "../outside",
            "UPPERCASE0123456789abcdef01234567",
            "0000",
        ] {
            assert!(rooted
                .replace_existing_file_staged(&staging, "file.bin", invalid, b"CHANGE")
                .is_err());
            assert_eq!(std::fs::read(allowed.join("file.bin")).unwrap(), b"SAFE");
        }
    }

    #[test]
    fn create_only_file_denies_external_hardlink_alias_without_changing_outside_bytes() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let original = outside.join("victim.bin");
        std::fs::write(&original, b"NEVER_MUTATE_PREEXISTING_BYTES").unwrap();
        let alias = root.join("alias.bin");
        std::fs::hard_link(&original, &alias).expect("real cross-root OS hardlink fixture");
        let cap = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&root, ambient_authority()).unwrap(),
        );
        assert!(cap
            .create_new_file("alias.bin", b"MALICIOUS_OVERWRITE")
            .is_err());
        assert_eq!(
            std::fs::read(&original).unwrap(),
            b"NEVER_MUTATE_PREEXISTING_BYTES"
        );
        assert_eq!(
            std::fs::read(&alias).unwrap(),
            b"NEVER_MUTATE_PREEXISTING_BYTES"
        );

        std::fs::create_dir(root.join("nested")).unwrap();
        cap.create_new_file("nested/genuine.bin", &[0, 1, 2, 255])
            .unwrap();
        assert_eq!(
            std::fs::read(root.join("nested/genuine.bin")).unwrap(),
            [0, 1, 2, 255]
        );
        assert!(cap
            .create_new_file("nested/genuine.bin", b"REWRITE")
            .is_err());
        assert_eq!(
            std::fs::read(root.join("nested/genuine.bin")).unwrap(),
            [0, 1, 2, 255]
        );
        assert_eq!(
            std::fs::read(&original).unwrap(),
            b"NEVER_MUTATE_PREEXISTING_BYTES"
        );
    }

    #[test]
    fn concurrent_create_only_writer_and_external_hardlink_racer_never_mutate_outside_bytes() {
        use std::sync::{Arc, Barrier};
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let victim = outside.join("victim.bin");
        let preserved = b"EXTERNAL_BYTES_MUST_NEVER_CHANGE";
        std::fs::write(&victim, preserved).unwrap();
        let capability = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&root, ambient_authority()).unwrap(),
        );
        for iteration in 0..16 {
            let alias_name = format!("raced_{iteration}.bin");
            let alias = root.join(&alias_name);
            let barrier = Arc::new(Barrier::new(2));
            let writer_gate = Arc::clone(&barrier);
            let attacker_gate = Arc::clone(&barrier);
            let writer_bytes = b"SAFE_NEW_FILE";
            let (writer, attacker) = std::thread::scope(|threads| {
                let writer = threads.spawn(|| {
                    writer_gate.wait();
                    capability
                        .create_new_file(&alias_name, writer_bytes)
                        .is_ok()
                });
                let attacker = threads.spawn(|| {
                    attacker_gate.wait();
                    std::fs::hard_link(&victim, &alias).is_ok()
                });
                (writer.join().unwrap(), attacker.join().unwrap())
            });
            assert_ne!(writer, attacker, "only one exclusive create may win");
            assert_eq!(std::fs::read(&victim).unwrap(), preserved);
            assert_eq!(
                std::fs::read(&alias).unwrap(),
                if writer {
                    writer_bytes.as_slice()
                } else {
                    preserved.as_slice()
                },
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_only_file_rejects_intermediate_symlink_to_external_directory() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"PRESERVED").unwrap();
        symlink(&outside, root.join("alias")).unwrap();
        let capability = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&root, ambient_authority()).unwrap(),
        );
        assert!(capability
            .create_new_file("alias/forbidden.bin", b"ATTACK")
            .is_err());
        assert!(!outside.join("forbidden.bin").exists());
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"PRESERVED"
        );
    }

    #[cfg(windows)]
    #[test]
    fn create_only_file_rejects_intermediate_ntfs_junction_to_external_directory() {
        use std::process::Command;
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("allowed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"PRESERVED").unwrap();
        let link = root.join("alias");
        let output = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .expect("Windows native junction fixture");
        assert!(output.status.success(), "junction setup failed: {output:?}");
        let capability = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&root, ambient_authority()).unwrap(),
        );
        assert!(capability
            .create_new_file("alias/forbidden.bin", b"ATTACK")
            .is_err());
        assert!(!outside.join("forbidden.bin").exists());
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"PRESERVED"
        );
    }

    #[test]
    fn create_only_file_rejects_unsafe_names_before_any_directory_mutation() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("allowed");
        std::fs::create_dir(&root).unwrap();
        let cap = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&root, ambient_authority()).unwrap(),
        );
        for path in [
            "fresh/../outside",
            "fresh/NUL",
            "fresh/CONOUT$.txt",
            "../escape",
            "C:/absolute",
            "new//file",
            "a\\b",
            "missing/child",
        ] {
            assert!(
                cap.create_new_file(path, b"data").is_err(),
                "unexpected creation for {path}"
            );
        }
        assert!(std::fs::read_dir(&root).unwrap().next().is_none());
        assert!(cap
            .create_new_file("too-large.bin", &vec![1; 1_048_577])
            .is_err());
        assert!(!root.join("too-large.bin").exists());
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
