//! T011: read-only OS registry high-water observation; never an authorization grant.
//! No policy DB is accepted solely on the strength of this module.
use crate::{verify_service_identity, IdentityDenied};
use std::{ffi::c_void, mem, ptr};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        AclSizeInformation,
        Authorization::{GetSecurityInfo, SE_REGISTRY_KEY},
        EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl, IsValidAcl, IsValidSid,
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE,
        ACE_HEADER, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    },
    System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS,
        KEY_READ, KEY_WOW64_64KEY, REG_BINARY, REG_OPTION_OPEN_LINK,
    },
};

// A separately privileged administrator must provision and protect this key.
// No caller input or environment variable may select a different authority.
const KEY_PATH: &str = "SOFTWARE\\JameDesktopCommander\\Authority\\EpochAnchor";
const VALUE_NAME: &str = "PolicyAnchorV1";
const ACCESS_ALLOWED_TYPE: u8 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trustee {
    System,
    Administrators,
    Service,
    Foreign,
}

#[derive(Clone, Copy)]
struct KeyAce {
    trustee: Trustee,
    mask: u32,
    flags: u8,
}

fn admit_acl(aces: &[KeyAce]) -> Result<(), IdentityDenied> {
    if aces.len() != 3 {
        return Err(IdentityDenied);
    }
    let (mut system, mut admins, mut service) = (false, false, false);
    for ace in aces {
        // No inherited ACEs or unexpected grants; exact masks are deliberate.
        if ace.flags != 0 {
            return Err(IdentityDenied);
        }
        match (ace.trustee, ace.mask) {
            (Trustee::System, KEY_ALL_ACCESS) if !system => system = true,
            (Trustee::Administrators, KEY_ALL_ACCESS) if !admins => admins = true,
            (Trustee::Service, KEY_READ) if !service => service = true,
            _ => return Err(IdentityDenied),
        }
    }
    if system && admins && service {
        Ok(())
    } else {
        Err(IdentityDenied)
    }
}

/// Version 1: single atomic REG_BINARY = epoch in network byte order (8 bytes)
/// followed by the 32-byte SHA-256 policy digest. Never read split values.
fn admissible_anchor(value_type: u32, data: &[u8]) -> Result<(u64, [u8; 32]), IdentityDenied> {
    if value_type != REG_BINARY {
        return Err(IdentityDenied);
    }
    crate::epoch_anchor_wire::parse_epoch_digest_wire(data)
}

/// Data-only observation. The key is never created or modified by this crate.
pub struct ObservedEpochFloor {
    epoch: u64,
    digest: [u8; 32],
}
impl ObservedEpochFloor {
    /// This exact check rejects replacement by *any* older/newer snapshot.
    /// The trusted policy updater must commit both snapshots explicitly.
    pub fn matches_snapshot(&self, snapshot_epoch: u64, snapshot_digest: &[u8; 32]) -> bool {
        self.epoch == snapshot_epoch && self.digest == *snapshot_digest
    }
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
struct SecurityDescriptor(*mut c_void);
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn trustee(sid: *mut c_void, service: &[u8]) -> Trustee {
    unsafe {
        if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
            Trustee::System
        } else if IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 {
            Trustee::Administrators
        } else if EqualSid(sid, service.as_ptr().cast_mut().cast()) != 0 {
            Trustee::Service
        } else {
            Trustee::Foreign
        }
    }
}

fn verify_protected_registry_acl(key: HKEY, service_sid: &[u8]) -> Result<(), IdentityDenied> {
    let mut owner: *mut c_void = ptr::null_mut();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor: *mut c_void = ptr::null_mut();
    // SAFETY: live registry handle borrowed by Win32; LocalFree owns the returned SD.
    let code = unsafe {
        GetSecurityInfo(
            key,
            SE_REGISTRY_KEY,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let _guard = SecurityDescriptor(descriptor);
    if code != 0 || descriptor.is_null() || owner.is_null() || acl.is_null() {
        return Err(IdentityDenied);
    }
    if unsafe { IsValidSid(owner) } == 0 || unsafe { IsValidAcl(acl) } == 0 {
        return Err(IdentityDenied);
    }
    if !matches!(
        trustee(owner, service_sid),
        Trustee::System | Trustee::Administrators
    ) {
        return Err(IdentityDenied);
    }
    let (mut control, mut revision) = (0u16, 0u32);
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(IdentityDenied);
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { mem::zeroed() };
    if unsafe {
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || info.AceCount != 3
    {
        return Err(IdentityDenied);
    }
    let mut aces = Vec::with_capacity(3);
    for i in 0..3 {
        let mut raw: *mut c_void = ptr::null_mut();
        if unsafe { GetAce(acl, i, &mut raw) } == 0 || raw.is_null() {
            return Err(IdentityDenied);
        }
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        let off = mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let len = header.AceSize as usize;
        if header.AceType != ACCESS_ALLOWED_TYPE
            || len < off + 8
            || len > info.AclBytesInUse as usize
        {
            return Err(IdentityDenied);
        }
        let sid = unsafe { raw.cast::<u8>().add(off) };
        let count = unsafe { *sid.add(1) } as usize;
        if count > 15 || 8 + 4 * count > len - off || unsafe { IsValidSid(sid.cast()) } == 0 {
            return Err(IdentityDenied);
        }
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        aces.push(KeyAce {
            trustee: trustee(sid.cast(), service_sid),
            mask: ace.Mask,
            flags: header.AceFlags,
        });
    }
    admit_acl(&aces)
}

/// Missing key, wrong principal, wrong ACL, missing/malformed value => DENY.
pub fn observe_fixed_epoch_floor() -> Result<ObservedEpochFloor, IdentityDenied> {
    verify_service_identity()?;
    let mut raw: HKEY = ptr::null_mut();
    let name = wide(KEY_PATH);
    // Never create; bind the 64-bit Registry view to avoid WOW64 alias drift.
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            REG_OPTION_OPEN_LINK,
            KEY_READ | KEY_WOW64_64KEY,
            &mut raw,
        )
    };
    if code != 0 || raw.is_null() {
        return Err(IdentityDenied);
    }
    let key = Key(raw);
    let service_sid = crate::windows_token::service_sid_bytes().map_err(|_| IdentityDenied)?;
    verify_protected_registry_acl(key.0, &service_sid)?;
    let mut kind = 0u32;
    let mut size = 40u32;
    let mut bytes = [0u8; 40];
    let label = wide(VALUE_NAME);
    // A single registry value prevents a torn pair of independently updated
    // epoch and digest values. Other lengths and types always deny.
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            label.as_ptr(),
            ptr::null(),
            &mut kind,
            bytes.as_mut_ptr(),
            &mut size,
        )
    };
    if code != 0 || size != 40 {
        return Err(IdentityDenied);
    }
    let (epoch, digest) = admissible_anchor(kind, &bytes)?;
    Ok(ObservedEpochFloor { epoch, digest })
}

/// Compare *exact, internally hashed policy bytes* with a separately
/// privileged, fixed-path HKLM epoch/digest anchor. No MCP request data may
/// supply this witness. All failures deny without creating or repairing state.
///
/// NON-RELEASE: this offline SQLite pathname is not yet an OS-pinned database
/// handle; the protected updater, crash reconciliation and privileged broker
/// have not been implemented. The returned bytes convey no filesystem grant.
pub fn verify_existing_policy_against_protected_registry(
    database: &std::path::Path,
) -> Result<jdc_authority_store::policy_bytes::VerifiedPolicy, IdentityDenied> {
    // Never touch a caller-supplied path until identity and the independent
    // immutable read-only registry authority pass kernel ACL verification.
    let witness = observe_fixed_epoch_floor()?;
    let store = jdc_authority_store::policy_bytes::PolicyBytesStore::open_existing(database)
        .map_err(|_| IdentityDenied)?;
    let policy = store.read_verified().map_err(|_| IdentityDenied)?;
    if !witness.matches_snapshot(policy.epoch(), policy.digest()) {
        return Err(IdentityDenied);
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn exact_acl() -> [KeyAce; 3] {
        [
            KeyAce {
                trustee: Trustee::System,
                mask: KEY_ALL_ACCESS,
                flags: 0,
            },
            KeyAce {
                trustee: Trustee::Administrators,
                mask: KEY_ALL_ACCESS,
                flags: 0,
            },
            KeyAce {
                trustee: Trustee::Service,
                mask: KEY_READ,
                flags: 0,
            },
        ]
    }
    #[test]
    fn protected_software_registry_admits_only_three_minimal_trustees() {
        assert_eq!(admit_acl(&exact_acl()), Ok(()));
        for trustee in [Trustee::Foreign, Trustee::Administrators, Trustee::System] {
            let mut bad = exact_acl();
            bad[2].trustee = trustee;
            assert_eq!(admit_acl(&bad), Err(IdentityDenied));
        }
        let mut bad = exact_acl();
        bad[2].mask |= 0x0002; // KEY_SET_VALUE
        assert_eq!(admit_acl(&bad), Err(IdentityDenied));
        let mut bad = exact_acl();
        bad[2].flags = 0x10; // inherited
        assert_eq!(admit_acl(&bad), Err(IdentityDenied));
        let mut extra = exact_acl().to_vec();
        extra.push(exact_acl()[2]);
        assert_eq!(admit_acl(&extra), Err(IdentityDenied));
    }
    #[test]
    fn atomic_epoch_and_digest_anchor_must_be_canonical_and_nonempty() {
        let mut canonical = [0xA5u8; 40];
        canonical[..8].copy_from_slice(&7u64.to_be_bytes());
        assert_eq!(
            admissible_anchor(REG_BINARY, &canonical),
            Ok((7, [0xA5; 32]))
        );
        assert_eq!(admissible_anchor(1, &canonical), Err(IdentityDenied));
        assert_eq!(
            admissible_anchor(REG_BINARY, &canonical[..39]),
            Err(IdentityDenied)
        );
        canonical[..8].fill(0);
        assert_eq!(
            admissible_anchor(REG_BINARY, &canonical),
            Err(IdentityDenied)
        );
        canonical[..8].copy_from_slice(&7u64.to_be_bytes());
        canonical[8..].fill(0);
        assert_eq!(
            admissible_anchor(REG_BINARY, &canonical),
            Err(IdentityDenied)
        );
    }
    #[test]
    fn independently_observed_high_water_rejects_older_or_newer_db_snapshot() {
        let digest = [0xA5; 32];
        let observed = ObservedEpochFloor { epoch: 7, digest };
        assert!(observed.matches_snapshot(7, &digest));
        assert!(!observed.matches_snapshot(6, &digest), "rollback must deny");
        assert!(
            !observed.matches_snapshot(8, &digest),
            "untrusted ahead-of-anchor must deny"
        );
        assert!(
            !observed.matches_snapshot(7, &[0xA6; 32]),
            "a forged same-epoch policy must not be accepted"
        );
    }
    #[test]
    fn unprivileged_process_cannot_join_policy_store_to_registry_authority() {
        let bogus = std::path::Path::new("never-a-valid-policy-database");
        assert!(verify_existing_policy_against_protected_registry(bogus).is_err());
    }

    #[test]
    fn ordinary_process_cannot_become_epoch_authority() {
        assert!(observe_fixed_epoch_floor().is_err());
    }
}
