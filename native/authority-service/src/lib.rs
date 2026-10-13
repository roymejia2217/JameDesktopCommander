//! Experimental T011-C4g operating-system identity preflight.
//! This DOES NOT authenticate an IPC peer, validate a policy store,
//! grant filesystem operations, or start a service.

pub mod token_policy;

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
    use std::{ffi::c_void, iter, mem, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{
            EqualSid, GetTokenInformation, LookupAccountNameW, TokenUser, SID_NAME_USE,
            TOKEN_QUERY, TOKEN_USER,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    // Account identity must be provisioned by the Windows SCM, independently
    // of any user-configurable JDC settings or caller-provided parameters.
    const SERVICE_NAME: &str = "NT SERVICE\\JameDesktopCommanderAuthority";

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    fn aligned_words(len: u32) -> Result<Vec<usize>, IdentityDenied> {
        let len = len as usize;
        if len == 0 || len > 4096 {
            return Err(IdentityDenied);
        }
        Ok(vec![0; len.div_ceil(mem::size_of::<usize>())])
    }

    pub fn verify() -> Result<(), IdentityDenied> {
        let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(iter::once(0)).collect();
        // An unresolved/not-yet-registered service account MUST deny.
        let mut sid_bytes = 0u32;
        let mut domain_chars = 0u32;
        let mut sid_use: SID_NAME_USE = 0;
        let probe = unsafe {
            LookupAccountNameW(
                ptr::null(),
                name.as_ptr(),
                ptr::null_mut(),
                &mut sid_bytes,
                ptr::null_mut(),
                &mut domain_chars,
                &mut sid_use,
            )
        };
        if probe != 0 || sid_bytes == 0 || sid_bytes > 256 || domain_chars > 256 {
            return Err(IdentityDenied);
        }
        let mut expected_sid = aligned_words(sid_bytes)?;
        let mut domain = vec![0u16; (domain_chars as usize).max(1)];
        let ok = unsafe {
            LookupAccountNameW(
                ptr::null(),
                name.as_ptr(),
                expected_sid.as_mut_ptr().cast::<c_void>(),
                &mut sid_bytes,
                domain.as_mut_ptr(),
                &mut domain_chars,
                &mut sid_use,
            )
        };
        if ok == 0 {
            return Err(IdentityDenied);
        }

        let mut raw_token: HANDLE = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
            return Err(IdentityDenied);
        }
        let token = OwnedHandle(raw_token);
        let mut token_bytes = 0u32;
        let probe = unsafe {
            GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut token_bytes)
        };
        if probe != 0 {
            return Err(IdentityDenied);
        }
        let mut buffer = aligned_words(token_bytes)?;
        if (token_bytes as usize) < mem::size_of::<TOKEN_USER>() {
            return Err(IdentityDenied);
        }
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast::<c_void>(),
                token_bytes,
                &mut token_bytes,
            )
        };
        if ok == 0 {
            return Err(IdentityDenied);
        }
        let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        if token_user.User.Sid.is_null() {
            return Err(IdentityDenied);
        }
        if unsafe {
            EqualSid(
                token_user.User.Sid,
                expected_sid.as_mut_ptr().cast::<c_void>(),
            )
        } == 0
        {
            return Err(IdentityDenied);
        }
        Ok(())
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
