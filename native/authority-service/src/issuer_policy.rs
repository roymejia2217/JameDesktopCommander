//! Exact policy-to-root binding for the native issuer (not yet a service).
//! Policy bytes do NOT confer authority without an OS-owned witness and service identity.
#[cfg(any(test, target_os = "linux"))]
use crate::handle_mkdir::RootedDirectory;
#[cfg(any(test, target_os = "linux"))]
use crate::IdentityDenied;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn protected_root_admission_denies_shared_mounts_wrong_principals_and_mutable_parents() {
        let parent = RootDomainSnapshot {
            uid: 0,
            gid: 0,
            mode: 0o40711,
            device: 100,
            mount_id: 10,
        };
        let isolated = RootDomainSnapshot {
            uid: 1001,
            gid: 1001,
            mode: 0o40700,
            device: 200,
            mount_id: 20,
        };
        assert!(admit_protected_root(parent, isolated, 1001, 1001));
        assert!(!admit_protected_root(
            parent,
            RootDomainSnapshot {
                mount_id: 10,
                ..isolated
            },
            1001,
            1001
        ));
        assert!(!admit_protected_root(
            parent,
            RootDomainSnapshot {
                device: 100,
                ..isolated
            },
            1001,
            1001
        ));
        assert!(!admit_protected_root(
            parent,
            RootDomainSnapshot {
                uid: 1002,
                ..isolated
            },
            1001,
            1001
        ));
        assert!(!admit_protected_root(
            parent,
            RootDomainSnapshot {
                gid: 1002,
                ..isolated
            },
            1001,
            1001
        ));
        assert!(!admit_protected_root(
            parent,
            RootDomainSnapshot {
                mode: 0o40770,
                ..isolated
            },
            1001,
            1001
        ));
        assert!(!admit_protected_root(
            RootDomainSnapshot {
                uid: 1001,
                ..parent
            },
            isolated,
            1001,
            1001
        ));
        assert!(!admit_protected_root(
            RootDomainSnapshot {
                mode: 0o40733,
                ..parent
            },
            isolated,
            1001,
            1001
        ));
        assert!(!admit_protected_root(parent, isolated, 0, 1001));
        assert!(!admit_protected_root(parent, isolated, 1001, 0));
        assert!(!admit_protected_root(
            parent,
            RootDomainSnapshot {
                mount_id: 0,
                ..isolated
            },
            1001,
            1001
        ));
    }

    const R: &str = "0123456789abcdef0123456789abcdef";
    const S: &str = "fedcba9876543210fedcba9876543210";
    fn policy(root_ref: &str, path: &str) -> Vec<u8> {
        format!(
            r#"{{"version":1,"mode":"restricted","roots":[{{"rootRef":{},"absolutePath":{}}}]}}"#,
            serde_json::to_string(root_ref).unwrap(),
            serde_json::to_string(path).unwrap()
        )
        .into_bytes()
    }
    #[test]
    fn valid_admin_policy_data_binds_one_root_without_issuing_permission() {
        let f = tempfile::tempdir().unwrap();
        let allowed = f.path().join("allowed");
        fs::create_dir(&allowed).unwrap();
        let raw = policy(R, allowed.to_str().unwrap());
        let binding = IssuerPolicy::decode_exact_for_test(&raw, 7, [1; 32]).unwrap();
        assert_eq!(binding.epoch(), 7);
        assert!(binding.open_root(S).is_err());
        assert!(binding.open_root(R).is_ok());
    }
    #[test]
    fn admin_candidate_root_preflight_rejects_missing_root_and_preserves_existing() {
        let f = tempfile::tempdir().unwrap();
        let allowed = f.path().join("allowed");
        let missing = f.path().join("missing");
        fs::create_dir(&allowed).unwrap();
        let valid = policy(R, allowed.to_str().unwrap());
        let invalid = policy(R, missing.to_str().unwrap());
        assert!(IssuerPolicy::validate_admin_existing_roots(&valid, 7, [1; 32]).is_ok());
        assert!(IssuerPolicy::validate_admin_existing_roots(&invalid, 7, [1; 32]).is_err());
        assert!(allowed.is_dir());
        assert!(!missing.exists());
    }
    #[test]
    fn untrusted_or_malformed_policy_cannot_bind_any_os_root() {
        let f = tempfile::tempdir().unwrap();
        let allowed = f.path().join("allowed");
        fs::create_dir(&allowed).unwrap();
        let path = allowed.to_str().unwrap();
        let good = policy(R, path);
        let path_json = serde_json::to_string(path).unwrap();
        let malformed = [
            Vec::new(),
            b"{}".to_vec(),
            [good.clone(), b" ".to_vec()].concat(),
            good.windows(1).count().to_string().into_bytes(),
            String::from_utf8(good.clone())
                .unwrap()
                .replace("\"version\":1", "\"version\":2")
                .into_bytes(),
            String::from_utf8(good.clone())
                .unwrap()
                .replace("\"mode\":\"restricted\"", "\"mode\":\"unrestricted\"")
                .into_bytes(),
            String::from_utf8(good.clone())
                .unwrap()
                .replace("\"roots\":[", "\"roots\":[]")
                .into_bytes(),
            policy("00000000000000000000000000000000", path),
            policy("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", path),
            policy(R, "."),
            policy(R, "/"),
        ];
        for raw in malformed {
            assert!(IssuerPolicy::decode_exact_for_test(&raw, 7, [1; 32]).is_err());
        }
        assert!(IssuerPolicy::decode_exact_for_test(&good, 0, [1; 32]).is_err());
        assert!(IssuerPolicy::decode_exact_for_test(&good, 7, [0; 32]).is_err());
        let duplicate = format!(
            r#"{{"version":1,"mode":"restricted","roots":[{{"rootRef":"{R}","absolutePath":{path_json}}},{{"rootRef":"{R}","absolutePath":{path_json}}}]}}"#
        );
        assert!(IssuerPolicy::decode_exact_for_test(duplicate.as_bytes(), 7, [1; 32]).is_err());
    }
    #[test]
    fn publisher_rejects_digest_consistent_but_semantically_invalid_policy() {
        // SQLite can carry SHA-consistent bytes that the native issuer cannot
        // interpret as an administrator-approved restricted root mapping.
        let bad = b"approved-policy-fixture";
        assert!(IssuerPolicy::validate_admin_candidate(bad, 2, [1; 32]).is_err());
        let good = policy(
            R,
            if cfg!(windows) {
                "C:\\safe-root"
            } else {
                "/safe-root"
            },
        );
        assert!(IssuerPolicy::validate_admin_candidate(&good, 2, [1; 32]).is_ok());
        let forged = String::from_utf8(good.clone())
            .unwrap()
            .replace("\"mode\":\"restricted\"", "\"mode\":\"unrestricted\"");
        assert!(IssuerPolicy::validate_admin_candidate(forged.as_bytes(), 2, [1; 32]).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn issuer_does_not_open_root_through_ntfs_junction_to_outside() {
        use std::process::Command;
        let f = tempfile::tempdir().unwrap();
        let outside = f.path().join("outside");
        let alias = f.path().join("alias");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"SECRET").unwrap();
        let result = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&alias)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "real junction fixture failed: {result:?}"
        );
        let binding =
            IssuerPolicy::decode_exact_for_test(&policy(R, alias.to_str().unwrap()), 7, [1; 32])
                .unwrap();
        assert!(binding.open_root(R).is_err());
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"SECRET");
    }
    #[cfg(windows)]
    #[test]
    fn issuer_rejects_intermediate_ntfs_junction_even_with_existing_child() {
        use std::process::Command;
        let f = tempfile::tempdir().unwrap();
        let allowed = f.path().join("allowed");
        let outside = f.path().join("outside");
        fs::create_dir(&allowed).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::create_dir(outside.join("real-child")).unwrap();
        let sentinel = outside.join("sentinel");
        fs::write(&sentinel, b"SECRET_NOT_AUTHORIZED").unwrap();
        let junction = allowed.join("redirect");
        let result = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "real junction fixture failed: {result:?}"
        );
        let requested = junction.join("real-child");
        let parsed = IssuerPolicy::decode_exact_for_test(
            &policy(R, requested.to_str().unwrap()),
            7,
            [1; 32],
        )
        .unwrap();
        assert!(parsed.open_root(R).is_err());
        assert_eq!(fs::read(sentinel).unwrap(), b"SECRET_NOT_AUTHORIZED");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_admin_policy_root_does_not_prove_dedicated_storage_custody() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("allowed");
        std::fs::create_dir(&root).unwrap();
        let policy =
            IssuerPolicy::decode_exact_for_test(&policy(R, root.to_str().unwrap()), 7, [1; 32])
                .unwrap();
        assert!(
            policy.open_root(R).is_ok(),
            "root binding alone must succeed"
        );
        assert!(
            policy.open_custodied_root(R).is_err(),
            "an ordinary user directory is not an attested isolated filesystem"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires isolated mount and real service principal in disposable hosted acceptance"]
    fn issuer_issues_only_an_attested_separate_filesystem_root() {
        let approved = std::env::var("JDC_T011_CUSTODIED_ROOT")
            .expect("the dedicated isolated storage mount must be supplied");
        crate::verify_service_identity()
            .expect("fixture must run under the real dedicated service UID/GID and NNP");
        let policy =
            IssuerPolicy::decode_exact_for_test(&policy(R, &approved), 7, [1; 32]).unwrap();
        let root = policy
            .open_custodied_root(R)
            .expect("an OS-separated 0700 dedicated root must be accepted");
        root.create_child("issuer-custody-positive")
            .expect("an authenticated service may create inside the isolated domain");
        assert!(std::path::Path::new(&approved)
            .join("issuer-custody-positive")
            .is_dir());
        assert!(
            policy.open_custodied_root(S).is_err(),
            "a valid but unrelated root reference cannot reuse the opened domain"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issuer_does_not_follow_symlink_root() {
        use std::os::unix::fs::symlink;
        let f = tempfile::tempdir().unwrap();
        let outside = f.path().join("outside");
        let alias = f.path().join("alias");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, &alias).unwrap();
        let p =
            IssuerPolicy::decode_exact_for_test(&policy(R, alias.to_str().unwrap()), 7, [1; 32])
                .unwrap();
        assert!(p.open_root(R).is_err());
    }
}
#[cfg(any(test, target_os = "linux"))]
use cap_fs_ext::DirExt;
#[cfg(any(test, target_os = "linux"))]
use cap_std::{ambient_authority, fs::Dir};
#[cfg(any(test, target_os = "linux"))]
use serde::{Deserialize, Serialize};
#[cfg(any(test, target_os = "linux"))]
use std::collections::HashSet;

/// Data validated against the *already OS-attested* admin policy snapshot.
/// This cannot be created from a client request, environment, or CLI option.
/// The public observation is NOT a way to mint operative directory handles.
/// ```compile_fail
/// use jdc_authority_service::issuer_policy::IssuerPolicy;
/// fn bypass(policy: IssuerPolicy) {
///     let privileged = policy.open_root("0123456789abcdef0123456789abcdef").unwrap();
///     privileged.create_child("unauthorized").unwrap();
/// }
/// ```
pub struct IssuerPolicy {
    epoch: u64,
    digest: [u8; 32],
    #[cfg(any(test, target_os = "linux"))]
    roots: Vec<PolicyRoot>,
}
#[cfg(any(test, target_os = "linux"))]
struct PolicyRoot {
    root_ref: String,
    disk_root: String,
}
#[cfg(any(test, target_os = "linux"))]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWire {
    version: u8,
    mode: String,
    roots: Vec<RootWire>,
}
#[cfg(any(test, target_os = "linux"))]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootWire {
    #[serde(rename = "rootRef")]
    root_ref: String,
    #[serde(rename = "absolutePath")]
    absolute_path: String,
}
// Single opened-handle snapshot, never a pathname or client-provided authority.
// Linux production populates this only from kernel statx + fstat.
#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy)]
struct RootDomainSnapshot {
    uid: u32,
    gid: u32,
    mode: u32,
    device: u64,
    mount_id: u64,
}

#[cfg(any(test, target_os = "linux"))]
fn admit_protected_root(
    parent: RootDomainSnapshot,
    root: RootDomainSnapshot,
    expected_uid: u32,
    expected_gid: u32,
) -> bool {
    // A separately mounted, OS-owned 0700 directory is the only admitted
    // restricted root. The mountpoint's immediate parent is root-admin-owned
    // and cannot be renamed by the service or another unprivileged principal.
    expected_uid != 0
        && expected_gid != 0
        && parent.uid == 0
        && parent.mount_id != 0
        && (parent.mode & 0o170000) == 0o040000
        && (parent.mode & 0o022) == 0
        && root.uid == expected_uid
        && root.gid == expected_gid
        && (root.mode & 0o170000) == 0o040000
        && (root.mode & 0o7777) == 0o700
        && root.mount_id != 0
        && root.mount_id != parent.mount_id
        && root.device != parent.device
}

// Read root ownership, mode, device and kernel mount from the SAME opened
// handle. No post-open ambient pathname checks or user-provided metadata.
#[cfg(target_os = "linux")]
fn observe_opened_domain(dir: &Dir) -> Result<RootDomainSnapshot, IdentityDenied> {
    use rustix::fs::{statx, AtFlags, StatxFlags};
    use std::{mem::MaybeUninit, os::fd::AsRawFd};
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(dir.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(IdentityDenied);
    }
    let stat = unsafe { stat.assume_init() };
    let mount =
        statx(dir, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID).map_err(|_| IdentityDenied)?;
    if (mount.stx_mask & StatxFlags::MNT_ID.bits()) == 0 || mount.stx_mnt_id == 0 {
        return Err(IdentityDenied);
    }
    Ok(RootDomainSnapshot {
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode,
        device: stat.st_dev,
        mount_id: mount.stx_mnt_id,
    })
}

// Only root-administrated ancestors may bind an isolated mountpoint. On
// disposable CI runners, /tmp is the conventional root-owned sticky 1777
// directory; the mounted child's DIRECT parent still must be nonwritable.
#[cfg(target_os = "linux")]
fn trusted_root_ancestor(observed: RootDomainSnapshot) -> bool {
    observed.uid == 0
        && (observed.mode & 0o170000) == 0o040000
        && ((observed.mode & 0o022) == 0 || (observed.mode & 0o7777) == 0o1777)
}

#[cfg(any(test, target_os = "linux"))]
fn root_components(path: &str) -> Result<(&str, Vec<&str>), IdentityDenied> {
    if path.len() > 4096 || path.chars().any(|c| c as u32 == 0) {
        return Err(IdentityDenied);
    }
    #[cfg(target_os = "linux")]
    let (anchor, suffix) = {
        if !path.starts_with('/') {
            return Err(IdentityDenied);
        }
        ("/", &path[1..])
    };
    #[cfg(windows)]
    let (anchor, suffix) = {
        let b = path.as_bytes();
        if b.len() < 4
            || !b[0].is_ascii_alphabetic()
            || b[1] != b':'
            || b[2] != 92
            || path.contains('/')
        {
            return Err(IdentityDenied);
        }
        (&path[..3], &path[3..])
    };
    let separator = if cfg!(windows) { char::from(92) } else { '/' };
    let parts: Vec<&str> = suffix.split(separator).collect();
    if parts.is_empty()
        || parts.len() > 64
        || parts
            .iter()
            .any(|p| !crate::canonical_request::safe_relative_path(p) || p.contains('/'))
    {
        return Err(IdentityDenied);
    }
    Ok((anchor, parts))
}
impl IssuerPolicy {
    /// Reject a candidate policy that is SHA-consistent in SQLite but would be
    /// rejected by the actual native issuer. This checks data semantics only;
    /// OS-rooted publisher custody and provenance are separate requirements.
    /// No root handles or caller privileges are created here.
    #[cfg(test)]
    pub(crate) fn validate_admin_candidate(
        bytes: &[u8],
        epoch: u64,
        digest: [u8; 32],
    ) -> Result<(), IdentityDenied> {
        Self::decode_verified(bytes, epoch, digest).map(|_| ())
    }

    /// Administrator-side *preflight*, never a grant: every declared root
    /// must currently be openable through the same no-follow OS-handle
    /// traversal used by the issuer. These handles are dropped immediately.
    /// The issuer MUST independently pin/revalidate them at bootstrap and
    /// before/after I/O; this check cannot linearize concurrent renames.
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn validate_admin_existing_roots(
        bytes: &[u8],
        epoch: u64,
        digest: [u8; 32],
    ) -> Result<(), IdentityDenied> {
        let policy = Self::decode_verified(bytes, epoch, digest)?;
        for root in &policy.roots {
            policy.open_root(&root.root_ref)?;
        }
        Ok(())
    }

    #[cfg(any(test, target_os = "linux"))]
    fn decode_verified(bytes: &[u8], epoch: u64, digest: [u8; 32]) -> Result<Self, IdentityDenied> {
        if epoch == 0 || digest == [0; 32] || bytes.is_empty() || bytes.len() > 65_536 {
            return Err(IdentityDenied);
        }
        let raw: PolicyWire = serde_json::from_slice(bytes).map_err(|_| IdentityDenied)?;
        if serde_json::to_vec(&raw).map_err(|_| IdentityDenied)? != bytes
            || raw.version != 1
            || raw.mode != "restricted"
            || raw.roots.is_empty()
            || raw.roots.len() > 16
        {
            return Err(IdentityDenied);
        }
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        let mut roots = Vec::with_capacity(raw.roots.len());
        for root in raw.roots {
            let ref_id = &root.root_ref;
            if ref_id.len() != 32
                || ref_id.bytes().all(|c| c == b'0')
                || !ref_id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                || root_components(&root.absolute_path).is_err()
                || !ids.insert(ref_id.clone())
                || !names.insert(root.absolute_path.to_ascii_lowercase())
            {
                return Err(IdentityDenied);
            }
            roots.push(PolicyRoot {
                root_ref: root.root_ref,
                disk_root: root.absolute_path,
            });
        }
        Ok(Self {
            epoch,
            digest,
            roots,
        })
    }
    /// Linux: the only production constructor reads the independently
    /// root-admin-owned epoch witness and OS-pinned policy SQLite snapshot.
    /// The CLI, MCP peer and Node configuration supply NO policy bytes.
    #[cfg(target_os = "linux")]
    pub fn from_os_attested() -> Result<Self, IdentityDenied> {
        let data = crate::linux_epoch_anchor::observe_matching_admin_policy_snapshot()?;
        Self::decode_verified(data.bytes(), data.epoch(), *data.digest())
    }
    #[cfg(test)]
    pub(crate) fn decode_exact_for_test(
        bytes: &[u8],
        epoch: u64,
        digest: [u8; 32],
    ) -> Result<Self, IdentityDenied> {
        Self::decode_verified(bytes, epoch, digest)
    }
    /// Root references are already validated against the OS-attested
    /// administrator-owned policy; only the issuer crate can enumerate them.
    #[cfg(target_os = "linux")]
    pub(crate) fn root_refs(&self) -> impl Iterator<Item = &str> {
        self.roots.iter().map(|r| r.root_ref.as_str())
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    /// Linux-only custody admission: the policy root must be the ROOT of a
    /// separately mounted filesystem, owned 0700 by the dedicated service UID
    /// and GID, directly below a root-admin-owned nonwritable parent. All
    /// preceding pathname components must stay on their original mount and
    /// be root-controlled (only root-owned sticky /tmp is tolerated).
    /// This is stricter than mere root-handle binding: it excludes arbitrary
    /// user-writable or shared-volume roots even when the admin policy is valid.
    /// Privileged admin namespace replacement remains outside this contract.
    /// Never accept expected identity or mount metadata from an MCP caller.
    #[cfg(target_os = "linux")]
    pub(crate) fn open_custodied_root(
        &self,
        root_ref: &str,
    ) -> Result<RootedDirectory, IdentityDenied> {
        #[cfg(not(test))]
        crate::verify_service_identity()?;
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        if uid == 0 || gid == 0 {
            return Err(IdentityDenied);
        }
        let selected = self
            .roots
            .iter()
            .find(|r| r.root_ref == root_ref)
            .ok_or(IdentityDenied)?;
        let (anchor, components) = root_components(&selected.disk_root)?;
        let mut current =
            Dir::open_ambient_dir(anchor, ambient_authority()).map_err(|_| IdentityDenied)?;
        let mut parent = observe_opened_domain(&current)?;
        if !trusted_root_ancestor(parent) {
            return Err(IdentityDenied);
        }
        for (index, part) in components.iter().enumerate() {
            let final_part = index + 1 == components.len();
            let child = current
                .open_dir_nofollow(part)
                .map_err(|_| IdentityDenied)?;
            let next = observe_opened_domain(&child)?;
            if final_part {
                if !admit_protected_root(parent, next, uid, gid) {
                    return Err(IdentityDenied);
                }
            } else if !trusted_root_ancestor(next)
                || next.mount_id != parent.mount_id
                || next.device != parent.device
            {
                return Err(IdentityDenied);
            }
            current = child;
            parent = next;
        }
        Ok(RootedDirectory::from_preopened(current))
    }

    /// Reopen no ambient client pathname. A trusted admin policy selects an
    /// absolute root; the OS volume root is the only initial ambient open.
    /// Every other path component is traversed under a capability handle.
    /// This is a ROOT-BINDING primitive, not a replay/revocation grant.
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn open_root(&self, root_ref: &str) -> Result<RootedDirectory, IdentityDenied> {
        let selected = self
            .roots
            .iter()
            .find(|r| r.root_ref == root_ref)
            .ok_or(IdentityDenied)?;
        let (anchor, parts) = root_components(&selected.disk_root)?;
        let mut opened =
            Dir::open_ambient_dir(anchor, ambient_authority()).map_err(|_| IdentityDenied)?;
        for part in parts {
            opened = opened.open_dir_nofollow(part).map_err(|_| IdentityDenied)?;
        }
        Ok(RootedDirectory::from_preopened(opened))
    }
}
