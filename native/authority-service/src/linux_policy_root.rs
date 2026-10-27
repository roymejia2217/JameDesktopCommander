//! Linux policy-directory custody boundary (non-release).
//! This module never authorizes policy bytes, a caller, or any filesystem command.
//! The service must still deny startup until authenticated IPC and durable policy
//! binding are independently demonstrated.
use crate::{verify_service_identity, IdentityDenied};
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const STATE_DIRECTORY: &str = "/var/lib/jdc-authority";

/// Opaque, kernel-opened directory descriptor, NOT a policy grant.
pub struct ObservedPolicyDirectory {
    fd: OwnedFd,
}

impl ObservedPolicyDirectory {
    /// Consume the owner/mode-checked pinned kernel descriptor exactly once.
    /// The caller must still bind it to an independently attested policy.
    pub(crate) fn into_verified_fd(self) -> OwnedFd {
        self.fd
    }

    /// Snapshot the opened inode identity; this is **not** an authorization token.
    /// A future broker must compare it to separately trusted policy provenance.
    pub fn file_identity(&self) -> Result<(u64, u64), IdentityDenied> {
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(self.fd.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
            return Err(IdentityDenied);
        }
        let st = unsafe { metadata.assume_init() };
        Ok((st.st_dev, st.st_ino))
    }
}

/// Only accept a pre-existing systemd-owned policy directory. Never create it.
/// The expected service UID/GID is inferred from kernel credentials *after*
/// verifying the independently provisioned dedicated service identity.
pub fn observe_provisioned_directory() -> Result<ObservedPolicyDirectory, IdentityDenied> {
    verify_service_identity()?;
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    open_verified_existing_directory(STATE_DIRECTORY, uid, gid)
}

fn open_verified_existing_directory(
    path: &str,
    expected_uid: libc::uid_t,
    expected_gid: libc::gid_t,
) -> Result<ObservedPolicyDirectory, IdentityDenied> {
    let components = validated_absolute_components(path)?;
    if expected_uid == 0 || expected_gid == 0 {
        return Err(IdentityDenied);
    }
    // SAFETY: fixed NUL-terminated absolute root literal; RAII owns the fd.
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root < 0 {
        return Err(IdentityDenied);
    }
    let mut cursor = unsafe { OwnedFd::from_raw_fd(root) };
    assert_trusted_directory(&cursor, expected_uid, expected_gid, false)?;
    for (index, component) in components.iter().enumerate() {
        let name = CString::new(*component).map_err(|_| IdentityDenied)?;
        // SAFETY: cursor is a live directory FD. O_NOFOLLOW prevents following
        // symlink aliases at every lookup; O_PATH retains the opened inode.
        let raw = unsafe {
            libc::openat(
                cursor.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(IdentityDenied);
        }
        let next = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_trusted_directory(
            &next,
            expected_uid,
            expected_gid,
            index + 1 == components.len(),
        )?;
        cursor = next;
    }
    Ok(ObservedPolicyDirectory { fd: cursor })
}

fn validated_absolute_components(path: &str) -> Result<Vec<&str>, IdentityDenied> {
    if path.len() > 4096 || !path.starts_with('/') || path == "/" || path.ends_with('/') {
        return Err(IdentityDenied);
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    if segments.is_empty()
        || segments.len() > 64
        || segments.iter().any(|seg| {
            seg.is_empty()
                || *seg == "."
                || *seg == ".."
                || seg.len() > 255
                || !seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b) || b == b'.')
        })
    {
        return Err(IdentityDenied);
    }
    Ok(segments)
}

fn assert_trusted_directory(
    fd: &OwnedFd,
    service_uid: libc::uid_t,
    service_gid: libc::gid_t,
    final_directory: bool,
) -> Result<(), IdentityDenied> {
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fd is owned and live; fstat initializes the output only on success.
    if unsafe { libc::fstat(fd.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(IdentityDenied);
    }
    let st = unsafe { metadata.assume_init() };
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(IdentityDenied);
    }
    if final_directory {
        // systemd StateDirectoryMode=0700; only the service may traverse/state-write.
        if st.st_uid != service_uid || st.st_gid != service_gid || (st.st_mode & 0o7777) != 0o700 {
            return Err(IdentityDenied);
        }
    } else if (st.st_uid != 0 && st.st_uid != service_uid) || (st.st_mode & 0o022) != 0 {
        // Every ancestor must resist group/other renames, even a sticky /tmp.
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absolute_grammar_rejects_ambiguous_or_traversing_components() {
        for path in [
            "",
            "/",
            "relative",
            "/tmp/",
            "/tmp//bad",
            "/tmp/./x",
            "/tmp/../x",
            "/tmp/with space",
        ] {
            assert!(
                validated_absolute_components(path).is_err(),
                "accepted {path:?}"
            );
        }
        assert_eq!(
            validated_absolute_components(STATE_DIRECTORY).unwrap(),
            vec!["var", "lib", "jdc-authority"]
        );
    }
    #[test]
    fn untrusted_temporary_ancestors_and_symlinks_are_not_policy_custody() {
        use std::os::unix::fs::PermissionsExt;
        let temp_mode = std::fs::metadata("/tmp").unwrap().permissions().mode();
        assert_ne!(temp_mode & 0o002, 0, "world-writable /tmp fixture required");
        let fixture = tempfile::tempdir_in("/tmp").unwrap();
        let root = fixture.path().join("state");
        std::fs::create_dir(&root).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert!(open_verified_existing_directory(root.to_str().unwrap(), uid, gid).is_err());

        let home = std::env::var_os("HOME").expect("Linux CI must provide HOME");
        let private = tempfile::tempdir_in(home).unwrap();
        let protected = private.path().join("state");
        std::fs::create_dir(&protected).unwrap();
        // CI umask is not the declared service StateDirectoryMode=0700.
        // Establish the positive control independently of runner defaults.
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mode = std::fs::metadata(&protected).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700, "valid policy-directory fixture required");
        assert!(
            open_verified_existing_directory(protected.to_str().unwrap(), uid, gid).is_ok(),
            "positive control must prove valid state was openable"
        );
        let alias = private.path().join("alias");
        std::os::unix::fs::symlink(&protected, &alias).unwrap();
        assert!(open_verified_existing_directory(alias.to_str().unwrap(), uid, gid).is_err());
    }
    #[test]
    fn verified_linux_state_directory_is_consumed_as_an_opened_staging_capability() {
        use crate::handle_mkdir::{ProtectedStagingDirectory, RootedDirectory};
        use cap_std::{ambient_authority, fs::Dir};
        use std::os::unix::fs::PermissionsExt;
        let home = std::env::var_os("HOME").expect("CI home directory required");
        let fixture = tempfile::tempdir_in(home).unwrap();
        let state = fixture.path().join("service-state");
        let allowed = fixture.path().join("allowed");
        std::fs::create_dir(&state).unwrap();
        std::fs::create_dir(&allowed).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(allowed.join("target.bin"), b"OLD").unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let observed = open_verified_existing_directory(state.to_str().unwrap(), uid, gid)
            .expect("existing protected state directory");
        let staging = ProtectedStagingDirectory::from_verified_linux_state(observed);
        let rooted = RootedDirectory::from_preopened(
            Dir::open_ambient_dir(&allowed, ambient_authority()).unwrap(),
        );
        rooted
            .replace_existing_file_staged(
                &staging,
                "target.bin",
                "0123456789abcdef0123456789abcdef",
                b"NEW",
            )
            .unwrap();
        assert_eq!(std::fs::read(allowed.join("target.bin")).unwrap(), b"NEW");
        assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
    }

    #[test]
    fn correctly_owned_nonwritable_ancestors_return_a_pinned_kernel_descriptor() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let home = std::env::var_os("HOME").expect("Linux CI must provide a home directory");
        let temp = tempfile::tempdir_in(home).expect("private fixture in user-owned HOME");
        let state = temp.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert_ne!(uid, 0, "dedicated nonroot positive control required");
        let observed = open_verified_existing_directory(state.to_str().unwrap(), uid, gid)
            .expect("real anchored fds with nonwritable ancestors must work");
        let original_ino = std::fs::metadata(&state).unwrap().ino();
        let moved = temp.path().join("renamed");
        std::fs::rename(&state, &moved).unwrap();
        let replacement = temp.path().join("state");
        std::os::unix::fs::symlink(&temp, &replacement).unwrap();
        assert!(open_verified_existing_directory(replacement.to_str().unwrap(), uid, gid).is_err());
        let (_, inode_after_rename) = observed.file_identity().unwrap();
        assert_eq!(inode_after_rename, original_ino);
    }

    #[test]
    fn final_wrong_permissions_or_gid_are_always_denied() {
        use std::os::unix::fs::PermissionsExt;
        let home = std::env::var_os("HOME").expect("Linux CI must provide a home directory");
        let temp = tempfile::tempdir_in(home).expect("private fixture in user-owned HOME");
        let root = temp.path().join("state");
        std::fs::create_dir(&root).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        if uid == 0 || gid == 0 {
            panic!("test must use nonroot principal");
        }
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(open_verified_existing_directory(root.to_str().unwrap(), uid, gid).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            open_verified_existing_directory(root.to_str().unwrap(), uid, gid.wrapping_add(1))
                .is_err()
        );
    }

    #[test]
    fn group_writable_parent_is_rejected_even_when_final_state_mode_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let home = std::env::var_os("HOME").expect("Linux CI must provide a home directory");
        let temp = tempfile::tempdir_in(home).expect("private fixture in user-owned HOME");
        let parent = temp.path().join("mutable");
        let state = parent.join("state");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o770)).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert!(open_verified_existing_directory(state.to_str().unwrap(), uid, gid).is_err());
    }

    #[test]
    fn ordinary_process_cannot_grant_itself_the_service_state_root() {
        assert!(observe_provisioned_directory().is_err());
        assert!(
            crate::handle_mkdir::ProtectedStagingDirectory::from_provisioned_linux_state().is_err(),
            "ordinary process must not bootstrap a service-owned staging capability"
        );
    }
}
