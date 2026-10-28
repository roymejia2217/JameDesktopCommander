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
