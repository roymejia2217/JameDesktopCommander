//! Windows-only read-only token observation for T011-C4o (non-release).
//! No public SCM authorization or service lifecycle is changed here.
use crate::token_policy::{
    bounded_buffer_span, bounded_sid_bytes, bounded_token_array, classify_token, TokenEvidence,
    TokenFinding,
};
use std::{ffi::c_void, iter, mem, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE},
    Security::{
        EqualSid, GetTokenInformation, IsWellKnownSid, LookupAccountNameW, LookupPrivilegeNameW,
        TokenGroups, TokenIntegrityLevel, TokenPrimary, TokenPrivileges, TokenRestrictedSids,
        TokenType, WinBuiltinAdministratorsSid, WinLocalSystemSid, LUID_AND_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES, SID_NAME_USE, TOKEN_GROUPS,
        TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_TYPE,
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
        for i in 0..count {
            let item = unsafe {
                ptr::read_unaligned(
                    base.add(i * mem::size_of::<SID_AND_ATTRIBUTES>())
                        .cast::<SID_AND_ATTRIBUTES>(),
                )
            };
            self.sid(item.Sid)?;
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
    let mut names = Vec::new();
    for i in 0..count {
        let slot = unsafe {
            ptr::read_unaligned(
                base.add(i * mem::size_of::<LUID_AND_ATTRIBUTES>())
                    .cast::<LUID_AND_ATTRIBUTES>(),
            )
        };
        if slot.Attributes & SE_PRIVILEGE_ENABLED == 0 {
            continue;
        }
        let mut buf = [0u16; 256];
        let mut chars = buf.len() as u32;
        if unsafe { LookupPrivilegeNameW(ptr::null(), &slot.Luid, buf.as_mut_ptr(), &mut chars) }
            == 0
            || chars == 0
            || chars as usize > buf.len()
        {
            return Err(TokenUnverifiable);
        }
        let name = String::from_utf16(&buf[..chars as usize]).map_err(|_| TokenUnverifiable)?;
        names.push(name);
    }
    Ok(names)
}
fn integrity_rid(info: &RawInfo) -> Result<u32, TokenUnverifiable> {
    let label: TOKEN_MANDATORY_LABEL = info.fixed()?;
    let sid = info.sid(label.Label.Sid)?;
    // Mandatory label SID: S-1-16-<integrity RID>.
    if sid[2..8] != [0, 0, 0, 0, 0, 16] {
        return Err(TokenUnverifiable);
    }
    let tail: [u8; 4] = sid[sid.len() - 4..]
        .try_into()
        .map_err(|_| TokenUnverifiable)?;
    Ok(u32::from_le_bytes(tail))
}
/// Read actual kernel-issued process token; caller cannot supply SID or claims.
/// This does NOT grant authority, and is not wired into the SCM lifecycle yet.
pub fn observe_current_process_token() -> Result<TokenFinding, TokenUnverifiable> {
    // C4g's independent virtual-account identity proof still applies.
    if crate::verify_service_identity().is_err() {
        return Ok(TokenFinding::BoundaryViolation);
    }
    let mut raw: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(TokenUnverifiable);
    }
    let token = Handle(raw);
    let token_type: TOKEN_TYPE = query(token.0, TokenType)?.fixed()?;
    let groups = query(token.0, TokenGroups)?;
    let normal_groups = groups.sid_groups()?;
    let mut elevated = false;
    for group in normal_groups {
        if group.Attributes & 0x4 == 0 {
            continue;
        }
        if unsafe { IsWellKnownSid(group.Sid, WinBuiltinAdministratorsSid) } != 0
            || unsafe { IsWellKnownSid(group.Sid, WinLocalSystemSid) } != 0
        {
            elevated = true;
        }
    }
    let restricted = query(token.0, TokenRestrictedSids)?;
    let expected = service_sid()?;
    let expected_sid = expected.words.as_ptr().cast_mut().cast();
    let mut matching_attributes = None;
    for group in restricted.sid_groups()? {
        if unsafe { EqualSid(group.Sid, expected_sid) } != 0
            && matching_attributes.replace(group.Attributes).is_some()
        {
            return Err(TokenUnverifiable);
        }
    }
    let integrity = integrity_rid(&query(token.0, TokenIntegrityLevel)?)?;
    let enabled = enabled_privileges(&query(token.0, TokenPrivileges)?)?;
    let names: Vec<&str> = enabled.iter().map(String::as_str).collect();
    Ok(classify_token(&TokenEvidence {
        identity_matches: true,
        is_primary: token_type == TokenPrimary,
        restricted_service_sid_attributes: matching_attributes,
        elevated_group_enabled: elevated,
        integrity_rid: Some(integrity),
        enabled_privileges: &names,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn invalid_kernel_token_handle_never_produces_a_snapshot() {
        assert!(query(ptr::null_mut(), TokenType).is_err());
    }
}
