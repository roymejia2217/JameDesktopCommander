//! Experimental T011-C4g operating-system identity preflight.
//! This DOES NOT authenticate an IPC peer, validate a policy store,
//! grant filesystem operations, or start a service.

pub mod token_policy;

// Never enable an IPC listener solely because peer credentials are observable.
// This module only reads kernel-verified Unix peer metadata; it grants nothing.
#[cfg(target_os = "linux")]
pub mod unix_peer;
#[cfg(any(target_os = "linux", test))]
mod peer_contract;

#[cfg(windows)]
pub mod windows_token;

/// This error never carries user-controlled credentials into diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityDenied;

/// Check actual kernel-issued process credentials against the expected,
/// independently provisioned service account; environment variables and
/// command-line claims are intentionally ignored.
pub fn verify_service_identity() -> Result<(), IdentityDenied> {
    #[cfg(windows)]
    {
        windows_identity::verify()
    }
    #[cfg(target_os = "linux")]
    {
        linux_identity::verify()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err(IdentityDenied)
    }
}

// Shared pure policy for platform-independent tests. The Linux verifier
// supplies its actual kernel getgroups(2) values; no caller-supplied names.
#[cfg(any(target_os = "linux", test))]
fn only_dedicated_supplementary_groups(groups: &[u32], expected_gid: u32) -> bool {
    expected_gid != 0 && groups.len() <= 32 && groups.iter().all(|&gid| gid == expected_gid)
}

#[cfg(target_os = "linux")]
mod linux_identity {
    use super::{only_dedicated_supplementary_groups, IdentityDenied};
    use std::{mem::MaybeUninit, ptr};
    // Provisioning MUST be performed by a distinct system administrator.
    const SERVICE_NAME: &[u8] = b"jdc-authority\0";

    // Group the kernel's real/effective/saved credential triples; all slots
    // must match the independently looked-up non-root service account.
    fn matches_dedicated_ids(uids: [u32; 3], gids: [u32; 3], expected: (u32, u32)) -> bool {
        let (expected_uid, expected_gid) = expected;
        expected_uid != 0
            && expected_gid != 0
            && uids == [expected_uid; 3]
            && gids == [expected_gid; 3]
    }

    pub fn verify() -> Result<(), IdentityDenied> {
        // Bounded NSS lookup; missing account, ERANGE and API errors DENY.
        let mut pwd = MaybeUninit::<libc::passwd>::zeroed();
        let mut result: *mut libc::passwd = ptr::null_mut();
        let mut scratch = [0 as libc::c_char; 16384];
        let code = unsafe {
            libc::getpwnam_r(
                SERVICE_NAME.as_ptr().cast(),
                pwd.as_mut_ptr(),
                scratch.as_mut_ptr(),
                scratch.len(),
                &mut result,
            )
        };
        if code != 0 || result.is_null() {
            return Err(IdentityDenied);
        }
        let pwd = unsafe { pwd.assume_init() };
        let mut ru = 0;
        let mut eu = 0;
        let mut su = 0;
        let mut rg = 0;
        let mut eg = 0;
        let mut sg = 0;
        if unsafe { libc::getresuid(&mut ru, &mut eu, &mut su) } != 0
            || unsafe { libc::getresgid(&mut rg, &mut eg, &mut sg) } != 0
        {
            return Err(IdentityDenied);
        }
        if !matches_dedicated_ids([ru, eu, su], [rg, eg, sg], (pwd.pw_uid, pwd.pw_gid)) {
            return Err(IdentityDenied);
        }

        // getresgid(2) does not report supplementary groups. Retaining a
        // foreign group can silently expand access despite matching UIDs.
        // Refuse oversized lists or a list that changes between reads.
        const MAX_GROUPS: i32 = 32;
        let count = unsafe { libc::getgroups(0, ptr::null_mut()) };
        if !(0..=MAX_GROUPS).contains(&count) {
            return Err(IdentityDenied);
        }
        let mut supplementary = vec![0 as libc::gid_t; count as usize];
        let seen = unsafe {
            libc::getgroups(
                count,
                if count == 0 {
                    ptr::null_mut()
                } else {
                    supplementary.as_mut_ptr()
                },
            )
        };
        if seen != count || !only_dedicated_supplementary_groups(&supplementary, pwd.pw_gid) {
            return Err(IdentityDenied);
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn dedicated_uid_gid_required_in_all_real_effective_saved_slots() {
            assert!(matches_dedicated_ids(
                [2001, 2001, 2001],
                [2002, 2002, 2002],
                (2001, 2002)
            ));
            for (uids, gids, expected) in [
                ([0, 0, 0], [0, 0, 0], (0, 0)),
                ([0, 2001, 2001], [2002, 2002, 2002], (2001, 2002)),
                ([2001, 0, 2001], [2002, 2002, 2002], (2001, 2002)),
                ([2001, 2001, 0], [2002, 2002, 2002], (2001, 2002)),
                ([2001, 2001, 2001], [0, 2002, 2002], (2001, 2002)),
                ([2001, 2001, 2001], [2002, 0, 2002], (2001, 2002)),
                ([2001, 2001, 2001], [2002, 2002, 0], (2001, 2002)),
                ([2001, 2001, 2001], [2002, 2002, 2002], (2001, 0)),
                ([2001, 2001, 2001], [2002, 2002, 2002], (0, 2002)),
                ([2003, 2003, 2003], [2002, 2002, 2002], (2001, 2002)),
                ([2001, 2001, 2001], [2003, 2003, 2003], (2001, 2002)),
            ] {
                assert!(!matches_dedicated_ids(uids, gids, expected));
            }
        }
    }
}
#[cfg(windows)]
mod windows_identity {
    use super::IdentityDenied;

    // Use the same bounded TokenUser query, SID validation, service SID
    // lookup and RAII token handle as the SCM observer. The independent
    // preflight still acquires its own handle and never grants operations.
    pub fn verify() -> Result<(), IdentityDenied> {
        crate::windows_token::verify_current_process_identity().map_err(|_| IdentityDenied)
    }
}

#[cfg(test)]
mod supplemental_group_tests {
    use super::only_dedicated_supplementary_groups;

    #[test]
    fn only_the_dedicated_service_group_may_be_supplementary() {
        assert!(only_dedicated_supplementary_groups(&[], 2002));
        assert!(only_dedicated_supplementary_groups(&[2002], 2002));
        assert!(!only_dedicated_supplementary_groups(&[2002, 65534], 2002));
        assert!(!only_dedicated_supplementary_groups(&[0], 2002));
        assert!(!only_dedicated_supplementary_groups(&[2002], 0));
        assert!(!only_dedicated_supplementary_groups(&[2002; 33], 2002));
    }
}
