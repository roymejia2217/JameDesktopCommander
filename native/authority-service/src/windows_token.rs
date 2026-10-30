//! Windows-only read-only token observation for T011-C4o (non-release).
//! No public SCM authorization or service lifecycle is changed here.
use crate::token_policy::{
    bounded_buffer_span, bounded_sid_bytes, bounded_token_array, classify_token, integrity_sid_rid,
    validated_enabled_privilege_indices, PrivilegeRecord, TokenEvidence, TokenFinding,
};
use std::{collections::HashSet, ffi::c_void, iter, mem, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE},
    Security::{
        EqualSid, GetTokenInformation, IsWellKnownSid, LookupAccountNameW, LookupPrivilegeNameW,
        TokenGroups, TokenIntegrityLevel, TokenPrimary, TokenPrivileges, TokenRestrictedSids,
        TokenType, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid, LUID_AND_ATTRIBUTES,
        SID_AND_ATTRIBUTES, SID_NAME_USE, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES,
        TOKEN_QUERY, TOKEN_TYPE, TOKEN_USER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
const SERVICE_NAME: &str = "NT SERVICE\\JameDesktopCommanderAuthority";
const MAX_INFO_BYTES: usize = 16_384;
const MAX_SID_BYTES: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenUnverifiable;
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct RawInfo {
    words: Vec<usize>,
    used: usize,
}

// Owned SID bytes and attributes, never a pointer to GetTokenInformation memory.
// Private, deliberately not Debug or Serializable and never an authorization grant.
struct OwnedSidGroup {
    sid: Vec<u8>,
    attributes: u32,
}
impl OwnedSidGroup {
    fn is_consistent(&self) -> bool {
        const ENABLED: u32 = 0x4;
        const DENY_ONLY: u32 = 0x10;
        bounded_sid_bytes(&self.sid) == Some(self.sid.len())
            && self.attributes & (ENABLED | DENY_ONLY) != (ENABLED | DENY_ONLY)
    }
}
impl RawInfo {
    fn addr(&self) -> usize {
        self.words.as_ptr() as usize
    }
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.used) }
    }
    fn fixed<T: Copy>(&self) -> Result<T, TokenUnverifiable> {
        if self.used < mem::size_of::<T>() {
            return Err(TokenUnverifiable);
        }
        Ok(unsafe { ptr::read_unaligned(self.words.as_ptr().cast::<T>()) })
    }
    // The SID must be entirely inside this allocation before any OS SID API.
    fn sid(&self, sid: *mut c_void) -> Result<&[u8], TokenUnverifiable> {
        let addr = sid as usize;
        if !bounded_buffer_span(self.addr(), self.used, addr, 8, 1) {
            return Err(TokenUnverifiable);
        }
        let offset = addr - self.addr();
        let remaining = &self.bytes()[offset..];
        let len = bounded_sid_bytes(remaining).ok_or(TokenUnverifiable)?;
        Ok(&remaining[..len])
    }
    fn copied_sid_group(
        &self,
        group: SID_AND_ATTRIBUTES,
    ) -> Result<OwnedSidGroup, TokenUnverifiable> {
        let observed = OwnedSidGroup {
            sid: self.sid(group.Sid)?.to_vec(),
            attributes: group.Attributes,
        };
        if !observed.is_consistent() {
            return Err(TokenUnverifiable);
        }
        Ok(observed)
    }
    fn sid_groups(&self) -> Result<Vec<SID_AND_ATTRIBUTES>, TokenUnverifiable> {
        let prefix = mem::offset_of!(TOKEN_GROUPS, Groups);
        if self.used < prefix {
            return Err(TokenUnverifiable);
        }
        let count: u32 = self.fixed()?;
        let count = count as usize;
        if !bounded_token_array(
            self.used,
            prefix,
            mem::size_of::<SID_AND_ATTRIBUTES>(),
            count,
        ) {
            return Err(TokenUnverifiable);
        }
        let base = unsafe { self.words.as_ptr().cast::<u8>().add(prefix) };
        let mut groups = Vec::with_capacity(count);
        let mut seen_sids = HashSet::with_capacity(count);
        for i in 0..count {
            let item = unsafe {
                ptr::read_unaligned(
                    base.add(i * mem::size_of::<SID_AND_ATTRIBUTES>())
                        .cast::<SID_AND_ATTRIBUTES>(),
                )
            };
            // Canonical SID bytes, not pointer identity, define uniqueness.
            // Reject duplicates before the buffer is passed to any OS SID API.
            if !seen_sids.insert(self.sid(item.Sid)?) {
                return Err(TokenUnverifiable);
            }
            groups.push(item);
        }
        Ok(groups)
    }
}
fn query(token: HANDLE, kind: i32) -> Result<RawInfo, TokenUnverifiable> {
    let mut required = 0u32;
    let first = unsafe { GetTokenInformation(token, kind, ptr::null_mut(), 0, &mut required) };
    if first != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || required == 0
        || (required as usize) > MAX_INFO_BYTES
    {
        return Err(TokenUnverifiable);
    }
    let mut words = vec![0usize; (required as usize).div_ceil(mem::size_of::<usize>())];
    let mut received = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            kind,
            words.as_mut_ptr().cast(),
            required,
            &mut received,
        )
    } == 0
        || received == 0
        || received > required
    {
        return Err(TokenUnverifiable);
    }
    Ok(RawInfo {
        words,
        used: received as usize,
    })
}
// Reuse the existing bounded, kernel-verified SID lookup; do not duplicate
// SID parsers or expose a public authorization token to MCP callers.
pub(crate) fn service_sid_bytes() -> Result<Vec<u8>, TokenUnverifiable> {
    let owner = service_sid()?;
    Ok(owner.sid(owner.words.as_ptr().cast_mut().cast())?.to_vec())
}

fn service_sid() -> Result<RawInfo, TokenUnverifiable> {
    let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(iter::once(0)).collect();
    let (mut sid_bytes, mut domain_chars, mut use_type) = (0u32, 0u32, 0 as SID_NAME_USE);
    let first = unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            ptr::null_mut(),
            &mut sid_bytes,
            ptr::null_mut(),
            &mut domain_chars,
            &mut use_type,
        )
    };
    if first != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || sid_bytes == 0
        || sid_bytes > MAX_SID_BYTES
        || domain_chars > 256
    {
        return Err(TokenUnverifiable);
    }
    let allocated_sid_bytes = sid_bytes;
    let mut words = vec![0usize; (sid_bytes as usize).div_ceil(mem::size_of::<usize>())];
    let mut domain = vec![0u16; (domain_chars as usize).max(1)];
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            words.as_mut_ptr().cast(),
            &mut sid_bytes,
            domain.as_mut_ptr(),
            &mut domain_chars,
            &mut use_type,
        )
    } == 0
        || sid_bytes == 0
        || sid_bytes > allocated_sid_bytes
    {
        return Err(TokenUnverifiable);
    }
    let sid = RawInfo {
        words,
        used: sid_bytes as usize,
    };
    sid.sid(sid.words.as_ptr().cast_mut().cast())?;
    Ok(sid)
}
// Resolve the complete inventory (including disabled entries) before
// classifying enabled names. Missing or duplicate native names deny.
fn resolve_enabled_privilege_names<F>(
    records: &[PrivilegeRecord],
    mut lookup: F,
) -> Result<Vec<String>, TokenUnverifiable>
where
    F: FnMut(usize) -> Result<String, TokenUnverifiable>,
{
    let enabled = validated_enabled_privilege_indices(records).ok_or(TokenUnverifiable)?;
    let mut seen_names = HashSet::with_capacity(records.len());
    let mut names = Vec::with_capacity(enabled.len());
    for index in 0..records.len() {
        let name = lookup(index)?;
        if name.is_empty() || !seen_names.insert(name.to_ascii_lowercase()) {
            return Err(TokenUnverifiable);
        }
        if enabled.binary_search(&index).is_ok() {
            names.push(name);
        }
    }
    Ok(names)
}

fn enabled_privileges(info: &RawInfo) -> Result<Vec<String>, TokenUnverifiable> {
    let prefix = mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    let count: u32 = info.fixed()?;
    let count = count as usize;
    if !bounded_token_array(
        info.used,
        prefix,
        mem::size_of::<LUID_AND_ATTRIBUTES>(),
        count,
    ) {
        return Err(TokenUnverifiable);
    }
    let base = unsafe { info.words.as_ptr().cast::<u8>().add(prefix) };
    let mut slots = Vec::with_capacity(count);
    let mut records = Vec::with_capacity(count);
    for index in 0..count {
        let slot = unsafe {
            ptr::read_unaligned(
                base.add(index * mem::size_of::<LUID_AND_ATTRIBUTES>())
                    .cast::<LUID_AND_ATTRIBUTES>(),
            )
        };
        records.push(PrivilegeRecord {
            luid_low: slot.Luid.LowPart,
            luid_high: slot.Luid.HighPart,
            attributes: slot.Attributes,
        });
        slots.push(slot);
    }
    resolve_enabled_privilege_names(&records, |index| {
        let mut buf = [0u16; 256];
        let mut chars = buf.len() as u32;
        if unsafe {
            LookupPrivilegeNameW(
                ptr::null(),
                &slots[index].Luid,
                buf.as_mut_ptr(),
                &mut chars,
            )
        } == 0
            || chars == 0
            || chars as usize > buf.len()
        {
            return Err(TokenUnverifiable);
        }
        String::from_utf16(&buf[..chars as usize]).map_err(|_| TokenUnverifiable)
    })
}
fn integrity_rid(info: &RawInfo) -> Result<u32, TokenUnverifiable> {
    let label: TOKEN_MANDATORY_LABEL = info.fixed()?;
    // RawInfo::sid performs pointer and complete-length checks first.
    // Pure parser insists on exactly one mandatory-integrity subauthority.
    let sid = info.sid(label.Label.Sid)?;
    integrity_sid_rid(sid).ok_or(TokenUnverifiable)
}
// Both C4g preflight and C4o SCM observation use these exact bounded
// Windows primitives, but each independent API owns and closes its handle.
fn open_current_process_token() -> Result<Handle, TokenUnverifiable> {
    let mut raw: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(TokenUnverifiable);
    }
    Ok(Handle(raw))
}

fn token_user_matches_service(
    token: HANDLE,
    expected: &RawInfo,
) -> Result<Option<Vec<u8>>, TokenUnverifiable> {
    let identity_info = query(token, TokenUser)?;
    let user: TOKEN_USER = identity_info.fixed()?;
    // Validate the entire kernel-supplied SID before calling EqualSid.
    let validated_sid = identity_info.sid(user.User.Sid)?;
    let expected_sid = expected.words.as_ptr().cast_mut().cast();
    if unsafe { EqualSid(user.User.Sid, expected_sid) } == 0 {
        return Ok(None);
    }
    // Copy only the verified matching identity; never retain a native pointer.
    Ok(Some(validated_sid.to_vec()))
}

/// Standalone C4g process identity preflight. It never grants access.
/// Any missing, forged or corrupt identity is rejected without disclosure.
pub(crate) fn verify_current_process_identity() -> Result<(), TokenUnverifiable> {
    let token = open_current_process_token()?;
    let expected = service_sid()?;
    if token_user_matches_service(token.0, &expected)?.is_some() {
        Ok(())
    } else {
        Err(TokenUnverifiable)
    }
}

// Sensitive token attributes remain exclusively in this Windows module.
// No Debug, serialization, persistence or public getter: a future evidence
// writer must first pass a separate, independently reviewed confidentiality
// and provenance contract. This structure itself cannot grant I/O.
struct VerifiedScmTokenSnapshot {
    is_primary: bool,
    restricted_service_sid_attributes: Option<u32>,
    elevated_group_enabled: bool,
    integrity_rid: u32,
    enabled_privileges: Vec<String>,
    normal_groups: Vec<OwnedSidGroup>,
    restricted_groups: Vec<OwnedSidGroup>,
    token_user_sid: Vec<u8>,
    service_account_sid: Vec<u8>,
}

fn unique_group_sids(groups: &[OwnedSidGroup]) -> bool {
    let mut seen = HashSet::with_capacity(groups.len());
    groups.iter().all(|group| seen.insert(group.sid.as_slice()))
}

impl VerifiedScmTokenSnapshot {
    fn classify(&self) -> TokenFinding {
        if bounded_sid_bytes(&self.token_user_sid) != Some(self.token_user_sid.len())
            || bounded_sid_bytes(&self.service_account_sid) != Some(self.service_account_sid.len())
            || self.token_user_sid != self.service_account_sid
        {
            return TokenFinding::Unverifiable;
        }
        if !unique_group_sids(&self.normal_groups)
            || !unique_group_sids(&self.restricted_groups)
            || self
                .normal_groups
                .iter()
                .chain(self.restricted_groups.iter())
                .any(|group| !group.is_consistent())
        {
            return TokenFinding::Unverifiable;
        }
        let names: Vec<&str> = self.enabled_privileges.iter().map(String::as_str).collect();
        classify_token(&TokenEvidence {
            identity_matches: true,
            is_primary: self.is_primary,
            restricted_service_sid_attributes: self.restricted_service_sid_attributes,
            elevated_group_enabled: self.elevated_group_enabled,
            integrity_rid: Some(self.integrity_rid),
            enabled_privileges: &names,
        })
    }
}

// All attributes originate from the one kernel-issued token handle.
// No raw SID pointers survive the query buffers; only copied, validated
// names/flags remain in this in-process snapshot.
fn verified_snapshot(
    token: HANDLE,
    expected: &RawInfo,
    matched_user_sid: Vec<u8>,
) -> Result<VerifiedScmTokenSnapshot, TokenUnverifiable> {
    let expected_sid = expected.words.as_ptr().cast_mut().cast();
    let service_account_sid = expected.sid(expected_sid)?.to_vec();
    let token_type: TOKEN_TYPE = query(token, TokenType)?.fixed()?;
    let groups = query(token, TokenGroups)?;
    let normal_groups = groups.sid_groups()?;
    let mut copied_normal_groups = Vec::with_capacity(normal_groups.len());
    let mut elevated = false;
    for group in normal_groups {
        // The native API checks the original bounded kernel SID pointer.
        if group.Attributes & 0x4 != 0
            && (unsafe { IsWellKnownSid(group.Sid, WinBuiltinAdministratorsSid) } != 0
                || unsafe { IsWellKnownSid(group.Sid, WinLocalSystemSid) } != 0)
        {
            elevated = true;
        }
        copied_normal_groups.push(groups.copied_sid_group(group)?);
    }
    let restricted = query(token, TokenRestrictedSids)?;
    let restricted_groups = restricted.sid_groups()?;
    let mut copied_restricted_groups = Vec::with_capacity(restricted_groups.len());
    let mut matching_attributes = None;
    for group in restricted_groups {
        if unsafe { EqualSid(group.Sid, expected_sid) } != 0
            && matching_attributes.replace(group.Attributes).is_some()
        {
            return Err(TokenUnverifiable);
        }
        copied_restricted_groups.push(restricted.copied_sid_group(group)?);
    }
    let integrity = integrity_rid(&query(token, TokenIntegrityLevel)?)?;
    let enabled = enabled_privileges(&query(token, TokenPrivileges)?)?;
    Ok(VerifiedScmTokenSnapshot {
        is_primary: token_type == TokenPrimary,
        restricted_service_sid_attributes: matching_attributes,
        elevated_group_enabled: elevated,
        integrity_rid: integrity,
        enabled_privileges: enabled,
        normal_groups: copied_normal_groups,
        restricted_groups: copied_restricted_groups,
        token_user_sid: matched_user_sid,
        service_account_sid,
    })
}

/// Read actual kernel-issued process token; caller cannot supply SID or claims.
/// SCM attests all attributes on one handle and remains deny-only.
pub fn observe_current_process_token() -> Result<TokenFinding, TokenUnverifiable> {
    let token = open_current_process_token()?;
    let expected = service_sid()?;
    let Some(user_sid) = token_user_matches_service(token.0, &expected)? else {
        return Ok(TokenFinding::IdentityMismatch);
    };
    let snapshot = verified_snapshot(token.0, &expected, user_sid)?;
    Ok(snapshot.classify())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_policy::scm_terminal_denial_code;

    fn synthetic_groups() -> RawInfo {
        let mut info = RawInfo {
            words: vec![0usize; 32],
            used: 32 * mem::size_of::<usize>(),
        };
        let sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0];
        let field = mem::offset_of!(TOKEN_GROUPS, Groups);
        let sid_offset = field + mem::size_of::<SID_AND_ATTRIBUTES>() + 8;
        unsafe {
            let base = info.words.as_mut_ptr().cast::<u8>();
            ptr::write_unaligned(base.cast::<u32>(), 1);
            ptr::write_unaligned(
                base.add(field).cast::<SID_AND_ATTRIBUTES>(),
                SID_AND_ATTRIBUTES {
                    Sid: base.add(sid_offset).cast(),
                    Attributes: 0x4,
                },
            );
            ptr::copy_nonoverlapping(sid.as_ptr(), base.add(sid_offset), sid.len());
        }
        info
    }

    #[test]
    fn duplicate_native_group_sid_is_unverifiable_even_with_identical_attributes() {
        let mut info = RawInfo {
            words: vec![0usize; 64],
            used: 64 * mem::size_of::<usize>(),
        };
        let offset = mem::offset_of!(TOKEN_GROUPS, Groups);
        let sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0];
        // Distinct, non-overlapping native SID allocations with identical
        // canonical content: both are structurally valid before duplicate check.
        unsafe {
            let base = info.words.as_mut_ptr().cast::<u8>();
            ptr::write_unaligned(base.cast::<u32>(), 2);
            for (index, sid_offset) in [128usize, 160usize].into_iter().enumerate() {
                ptr::copy_nonoverlapping(sid.as_ptr(), base.add(sid_offset), sid.len());
                ptr::write_unaligned(
                    base.add(offset + index * mem::size_of::<SID_AND_ATTRIBUTES>())
                        .cast::<SID_AND_ATTRIBUTES>(),
                    SID_AND_ATTRIBUTES {
                        Sid: base.add(sid_offset).cast(),
                        Attributes: 0x4,
                    },
                );
                assert_eq!(info.sid(base.add(sid_offset).cast()).unwrap(), sid);
            }
        }
        assert!(info.sid_groups().is_err());
    }

    #[test]
    fn copied_group_sid_survives_original_kernel_buffer_mutation() {
        let mut raw = synthetic_groups();
        let item = raw.sid_groups().unwrap().remove(0);
        let copied = raw.copied_sid_group(item).unwrap();
        let expected = [1u8, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0];
        assert_eq!(copied.sid, expected);
        assert_eq!(copied.attributes, 0x4);
        assert!(copied.is_consistent());
        // Alter the originating token allocation after copying.
        let sid_offset = item.Sid as usize - raw.addr();
        unsafe {
            *raw.words.as_mut_ptr().cast::<u8>().add(sid_offset + 8) = 42;
        }
        assert_eq!(
            copied.sid, expected,
            "a copied SID must not alias the raw buffer"
        );
        assert_ne!(raw.sid(item.Sid).unwrap(), copied.sid.as_slice());
        let mut impossible = copied;
        impossible.attributes = 0x14; // enabled and deny-only simultaneously
        assert!(!impossible.is_consistent());
        let invalid_pointer = SID_AND_ATTRIBUTES {
            Sid: (raw.addr() + raw.used + 8) as *mut c_void,
            Attributes: 0x4,
        };
        assert!(raw.copied_sid_group(invalid_pointer).is_err());
    }

    #[test]
    fn kernel_buffer_sid_must_be_inside_allocation() {
        let mut info = synthetic_groups();
        assert_eq!(info.sid_groups().unwrap().len(), 1);
        let header = mem::offset_of!(TOKEN_GROUPS, Groups);
        let outside = (info.addr() + info.used + 8) as *mut c_void;
        unsafe {
            let base = info.words.as_mut_ptr().cast::<u8>();
            ptr::write_unaligned(
                base.add(header).cast::<SID_AND_ATTRIBUTES>(),
                SID_AND_ATTRIBUTES {
                    Sid: outside,
                    Attributes: 0x4,
                },
            );
        }
        assert!(info.sid_groups().is_err());
    }

    #[test]
    fn kernel_buffer_count_and_sid_revision_are_checked() {
        let mut info = synthetic_groups();
        unsafe {
            ptr::write_unaligned(info.words.as_mut_ptr().cast::<u32>(), 129);
        }
        assert!(info.sid_groups().is_err());
        let mut info = synthetic_groups();
        let sid_offset =
            mem::offset_of!(TOKEN_GROUPS, Groups) + mem::size_of::<SID_AND_ATTRIBUTES>() + 8;
        unsafe {
            *info.words.as_mut_ptr().cast::<u8>().add(sid_offset) = 2;
        }
        assert!(info.sid_groups().is_err());
    }

    #[test]
    fn token_user_sid_pointer_and_complete_length_are_bounded() {
        // A synthetic TOKEN_USER layout must not make a forged kernel
        // pointer readable just because its fixed-size header is present.
        let mut info = RawInfo {
            words: vec![0usize; 16],
            used: 16 * mem::size_of::<usize>(),
        };
        let base = info.words.as_mut_ptr().cast::<u8>();
        let forged = TOKEN_USER {
            User: SID_AND_ATTRIBUTES {
                Sid: (info.addr() + info.used + 8) as *mut c_void,
                Attributes: 0,
            },
        };
        unsafe {
            ptr::write_unaligned(base.cast::<TOKEN_USER>(), forged);
        }
        let user: TOKEN_USER = info.fixed().unwrap();
        assert!(info.sid(user.User.Sid).is_err());

        let sid_offset = mem::size_of::<TOKEN_USER>() + 8;
        let incomplete = [1u8, 2, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0];
        unsafe {
            ptr::write_unaligned(
                base.cast::<TOKEN_USER>(),
                TOKEN_USER {
                    User: SID_AND_ATTRIBUTES {
                        Sid: base.add(sid_offset).cast(),
                        Attributes: 0,
                    },
                },
            );
            ptr::copy_nonoverlapping(incomplete.as_ptr(), base.add(sid_offset), incomplete.len());
        }
        // One subauthority is missing; never call EqualSid.
        info.used = sid_offset + incomplete.len();
        let user: TOKEN_USER = info.fixed().unwrap();
        assert!(info.sid(user.User.Sid).is_err());
    }
    #[test]
    fn standalone_preflight_rejects_ordinary_process_identity() {
        // The CI process is not the temporary SCM virtual service account.
        assert!(verify_current_process_identity().is_err());
    }

    #[test]
    fn native_integrity_label_rejects_invalid_sid_pointer_and_extra_authority() {
        let mut info = RawInfo {
            words: vec![0usize; 16],
            used: 16 * mem::size_of::<usize>(),
        };
        let sid_offset = mem::size_of::<TOKEN_MANDATORY_LABEL>() + 8;
        let base = info.words.as_mut_ptr().cast::<u8>();
        let medium = [1u8, 1, 0, 0, 0, 0, 0, 16, 0, 32, 0, 0];
        unsafe {
            ptr::write_unaligned(
                base.cast::<TOKEN_MANDATORY_LABEL>(),
                TOKEN_MANDATORY_LABEL {
                    Label: SID_AND_ATTRIBUTES {
                        Sid: base.add(sid_offset).cast(),
                        Attributes: 0,
                    },
                },
            );
            ptr::copy_nonoverlapping(medium.as_ptr(), base.add(sid_offset), medium.len());
        }
        assert_eq!(integrity_rid(&info), Ok(0x2000));
        unsafe {
            *base.add(sid_offset + 1) = 2;
        }
        // The declared second subauthority has not been provided.
        info.used = sid_offset + 12;
        assert!(integrity_rid(&info).is_err());

        unsafe {
            ptr::write_unaligned(
                base.cast::<TOKEN_MANDATORY_LABEL>(),
                TOKEN_MANDATORY_LABEL {
                    Label: SID_AND_ATTRIBUTES {
                        Sid: (info.addr() + info.used + 8) as *mut c_void,
                        Attributes: 0,
                    },
                },
            );
        }
        assert!(integrity_rid(&info).is_err());
    }

    #[test]
    fn native_name_resolution_fails_closed_even_for_disabled_luids() {
        let records = [
            PrivilegeRecord {
                luid_low: 3,
                luid_high: 0,
                attributes: 0,
            },
            PrivilegeRecord {
                luid_low: 4,
                luid_high: 0,
                attributes: 0x2,
            },
        ];
        assert_eq!(
            resolve_enabled_privilege_names(&records, |i| {
                Ok(["SeChangeNotifyPrivilege", "SeImpersonatePrivilege"][i].into())
            }),
            Ok(vec!["SeImpersonatePrivilege".to_string()])
        );
        assert_eq!(
            resolve_enabled_privilege_names(&records, |i| {
                if i == 0 {
                    Err(TokenUnverifiable)
                } else {
                    Ok("SeImpersonatePrivilege".into())
                }
            }),
            Err(TokenUnverifiable)
        );
        assert_eq!(
            resolve_enabled_privilege_names(&records, |_| Ok("SeChangeNotifyPrivilege".into())),
            Err(TokenUnverifiable)
        );
        assert_eq!(
            resolve_enabled_privilege_names(&records, |_| Ok(String::new())),
            Err(TokenUnverifiable)
        );
    }

    #[test]
    fn in_process_verified_snapshot_keeps_privilege_names_private_and_deny_only() {
        let mut snapshot = VerifiedScmTokenSnapshot {
            is_primary: true,
            restricted_service_sid_attributes: Some(0x4),
            elevated_group_enabled: false,
            integrity_rid: 0x2000,
            enabled_privileges: vec!["SeChangeNotifyPrivilege".to_owned()],
            normal_groups: vec![],
            restricted_groups: vec![],
            token_user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0],
            service_account_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0],
        };
        assert_eq!(
            snapshot.classify(),
            TokenFinding::PrivilegeBaselineUnreviewed
        );
        assert_eq!(scm_terminal_denial_code(Some(snapshot.classify())), 3);
        snapshot.enabled_privileges = vec!["SeDebugPrivilege".to_owned()];
        assert_eq!(snapshot.classify(), TokenFinding::BoundaryViolation);
        snapshot.enabled_privileges.clear();
        assert_eq!(snapshot.classify(), TokenFinding::ObservedDenyOnly);
        assert_eq!(scm_terminal_denial_code(Some(snapshot.classify())), 1);
        snapshot.restricted_groups.push(OwnedSidGroup {
            sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0],
            attributes: 0x14, // structurally inconsistent: enabled + deny-only
        });
        assert_eq!(snapshot.classify(), TokenFinding::Unverifiable);
        snapshot.restricted_groups.clear();
        let sid = vec![1, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0];
        snapshot.normal_groups = vec![
            OwnedSidGroup {
                sid: sid.clone(),
                attributes: 0x4,
            },
            OwnedSidGroup {
                sid: sid.clone(),
                attributes: 0x4,
            },
        ];
        assert_eq!(snapshot.classify(), TokenFinding::Unverifiable);
        snapshot.normal_groups.clear();
        snapshot.restricted_groups = vec![
            OwnedSidGroup {
                sid: sid.clone(),
                attributes: 0x4,
            },
            OwnedSidGroup {
                sid,
                attributes: 0x10,
            },
        ];
        assert_eq!(snapshot.classify(), TokenFinding::Unverifiable);
        snapshot.restricted_groups.clear();
        // The two TOKEN_GROUPS classes are distinct inventories: overlap
        // between their SIDs is permitted, duplication within either is not.
        snapshot.normal_groups = vec![OwnedSidGroup {
            sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0],
            attributes: 0x4,
        }];
        snapshot.restricted_groups = vec![OwnedSidGroup {
            sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0],
            attributes: 0x4,
        }];
        assert_eq!(snapshot.classify(), TokenFinding::ObservedDenyOnly);
        snapshot.normal_groups.clear();
        snapshot.restricted_groups.clear();
        snapshot.token_user_sid[8] = 99;
        assert_eq!(snapshot.classify(), TokenFinding::Unverifiable);
        snapshot.token_user_sid[8] = 80;
        snapshot.service_account_sid.truncate(9);
        assert_eq!(snapshot.classify(), TokenFinding::Unverifiable);
        snapshot.service_account_sid = vec![1, 1, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0];
        snapshot.integrity_rid = 0;
        assert_eq!(snapshot.classify(), TokenFinding::Unverifiable);
    }

    #[test]
    fn invalid_kernel_token_handle_never_produces_a_snapshot() {
        assert!(query(ptr::null_mut(), TokenType).is_err());
    }
}
