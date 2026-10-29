//! Bounded Windows ACL decoding. Never interpret GetAce pointers as Rust references.
//! The final reader must constrain all relative offsets within the copied
//! GetSecurityInfo self-relative security descriptor.
use crate::IdentityDenied;

pub(crate) struct AllowedAce {
    pub(crate) sid: Vec<u8>,
    pub(crate) mask: u32,
    pub(crate) flags: u8,
}

/// Decode only three standard allow ACEs from copied, already bounded
/// Win32 ACL bytes. All untrusted lengths and offsets are checked as slices.
pub(crate) fn parse_three_allowed_aces(raw: &[u8]) -> Result<Vec<AllowedAce>, IdentityDenied> {
    use windows_sys::Win32::Security::{ACCESS_ALLOWED_ACE, ACL};
    const ACL_HEADER: usize = std::mem::size_of::<ACL>();
    const ACE_SID_OFFSET: usize = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if raw.len() < ACL_HEADER || raw.len() > u16::MAX as usize {
        return Err(IdentityDenied);
    }
    let declared_size = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let count = u16::from_le_bytes([raw[4], raw[5]]) as usize;
    if declared_size < raw.len() || count != 3 {
        return Err(IdentityDenied);
    }
    let mut cursor = ACL_HEADER;
    let mut result = Vec::with_capacity(3);
    for _ in 0..3 {
        let header = raw
            .get(cursor..cursor.checked_add(4).ok_or(IdentityDenied)?)
            .ok_or(IdentityDenied)?;
        let length = u16::from_le_bytes([header[2], header[3]]) as usize;
        if header[0] != 0 || length < ACE_SID_OFFSET + 8 {
            return Err(IdentityDenied);
        }
        let end = cursor.checked_add(length).ok_or(IdentityDenied)?;
        let ace = raw.get(cursor..end).ok_or(IdentityDenied)?;
        let sid = ace.get(ACE_SID_OFFSET..).ok_or(IdentityDenied)?;
        let count = *sid.get(1).ok_or(IdentityDenied)? as usize;
        if sid[0] != 1 || count > 15 || sid.len() != 8 + count * 4 {
            return Err(IdentityDenied);
        }
        let mask_bytes: [u8; 4] = ace
            .get(4..8)
            .ok_or(IdentityDenied)?
            .try_into()
            .map_err(|_| IdentityDenied)?;
        result.push(AllowedAce {
            sid: sid.to_vec(),
            mask: u32::from_le_bytes(mask_bytes),
            flags: header[1],
        });
        cursor = end;
    }
    if cursor != raw.len() {
        return Err(IdentityDenied);
    }
    Ok(result)
}

/// One owned copy of the checked security descriptor's allowlist.
pub(crate) struct ObservedAcl {
    pub(crate) owner_sid: Vec<u8>,
    pub(crate) aces: Vec<AllowedAce>,
}

fn component_offset(
    descriptor_address: usize,
    descriptor_len: usize,
    pointer_address: usize,
    length: usize,
) -> Result<usize, IdentityDenied> {
    let offset = pointer_address
        .checked_sub(descriptor_address)
        .ok_or(IdentityDenied)?;
    if offset.checked_add(length).ok_or(IdentityDenied)? > descriptor_len {
        return Err(IdentityDenied);
    }
    Ok(offset)
}

/// # Safety
/// descriptor, owner and dacl MUST be outputs from the same successful
/// GetSecurityInfo call, and its LocalAlloc descriptor must remain live for
/// this entire call. The independent Win32 API validates the descriptor's
/// layout; no borrowed ACE/owner pointer escapes into Rust.
///
/// The two callers still enforce their respective exact ACL rights and flags.
pub(crate) unsafe fn observe_three_aces(
    descriptor: *mut std::ffi::c_void,
    owner: *mut std::ffi::c_void,
    dacl: *mut windows_sys::Win32::Security::ACL,
    info: &windows_sys::Win32::Security::ACL_SIZE_INFORMATION,
) -> Result<ObservedAcl, IdentityDenied> {
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorControl, GetSecurityDescriptorLength, IsValidSecurityDescriptor,
        IsValidSid, ACL, SE_SELF_RELATIVE,
    };
    if descriptor.is_null() || owner.is_null() || dacl.is_null() || info.AceCount != 3 {
        return Err(IdentityDenied);
    }
    if unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Err(IdentityDenied);
    }
    let (mut control, mut revision) = (0u16, 0u32);
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_SELF_RELATIVE == 0
    {
        return Err(IdentityDenied);
    }

    let descriptor_len = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    if !(20..=131_072).contains(&descriptor_len) {
        return Err(IdentityDenied);
    }
    let acl_used = usize::try_from(info.AclBytesInUse).map_err(|_| IdentityDenied)?;
    if acl_used < std::mem::size_of::<ACL>() || acl_used > u16::MAX as usize {
        return Err(IdentityDenied);
    }
    let base = descriptor as usize;
    let owner_offset = component_offset(base, descriptor_len, owner as usize, 8)?;
    let acl_offset = component_offset(base, descriptor_len, dacl as usize, acl_used)?;

    // SAFETY: GetSecurityInfo returned a live self-relative LocalAlloc buffer,
    // independently checked by IsValidSecurityDescriptor; its exact kernel-
    // supplied length is bounded above. Both component offsets were verified
    // numerically before any access. The guard in the caller retains ownership.
    let bytes = unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), descriptor_len) };
    let owner_count = bytes[owner_offset + 1] as usize;
    if bytes[owner_offset] != 1 || owner_count > 15 {
        return Err(IdentityDenied);
    }
    let owner_len = 8 + 4 * owner_count;
    let owner_sid = bytes
        .get(owner_offset..owner_offset + owner_len)
        .ok_or(IdentityDenied)?
        .to_vec();
    if unsafe { IsValidSid(owner_sid.as_ptr().cast_mut().cast()) } == 0 {
        return Err(IdentityDenied);
    }

    let acl = bytes
        .get(acl_offset..acl_offset + acl_used)
        .ok_or(IdentityDenied)?;
    let aces = parse_three_allowed_aces(acl)?;
    for ace in &aces {
        if unsafe { IsValidSid(ace.sid.as_ptr().cast_mut().cast()) } == 0 {
            return Err(IdentityDenied);
        }
    }
    Ok(ObservedAcl { owner_sid, aces })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut acl = vec![2, 0, 0, 0, 3, 0, 0, 0];
        for mask in [0x001f_01ff_u32, 0x001f_01ff, 0x0003_01bf] {
            let sid: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
            acl.extend_from_slice(&[0, 3]); // ACCESS_ALLOWED, OI+CI
            acl.extend_from_slice(&(8u16 + sid.len() as u16).to_le_bytes());
            acl.extend_from_slice(&mask.to_le_bytes());
            acl.extend_from_slice(&sid);
        }
        let len = u16::try_from(acl.len()).unwrap().to_le_bytes();
        acl[2..4].copy_from_slice(&len);
        acl
    }

    #[test]
    fn descriptor_component_bounds_reject_escape_and_integer_overflow() {
        assert_eq!(component_offset(0x1000, 128, 0x1008, 8), Ok(8));
        assert!(component_offset(0x1000, 128, 0x0fff, 8).is_err());
        assert!(component_offset(0x1000, 128, 0x107f, 2).is_err());
        assert!(component_offset(usize::MAX - 2, 10, usize::MAX - 1, usize::MAX).is_err());
    }

    #[test]
    fn preallocated_acl_slack_does_not_invalidate_used_bytes() {
        let mut bytes = fixture();
        let claimed_size = u16::try_from(bytes.len() + 8).unwrap().to_le_bytes();
        bytes[2..4].copy_from_slice(&claimed_size);
        assert_eq!(parse_three_allowed_aces(&bytes).unwrap().len(), 3);
    }

    #[test]
    fn valid_three_aces_decode_without_raw_pointer_dereferences() {
        let aces = parse_three_allowed_aces(&fixture()).unwrap();
        assert_eq!(aces.len(), 3);
        assert_eq!(aces[0].mask, 0x001f_01ff);
        assert_eq!(aces[2].mask, 0x0003_01bf);
        assert_eq!(aces[1].flags, 3);
        assert_eq!(aces[0].sid.len(), 12);
    }

    #[test]
    fn malformed_ace_lengths_sid_counts_and_types_deny() {
        let original = fixture();
        let mut variants = Vec::new();
        let mut zero_size = original.clone();
        zero_size[10..12].copy_from_slice(&0u16.to_le_bytes());
        variants.push(zero_size);
        let mut oversized = original.clone();
        oversized[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
        variants.push(oversized);
        let mut overcount = original.clone();
        overcount[17] = 16; // SID SubAuthorityCount > 15
        variants.push(overcount);
        let mut wrong_type = original.clone();
        wrong_type[8] = 1; // ACCESS_DENIED, never silently accept
        variants.push(wrong_type);
        let mut wrong_revision = original.clone();
        wrong_revision[16] = 2; // unsupported SID revision
        variants.push(wrong_revision);
        let mut wrong_acl_count = original.clone();
        wrong_acl_count[4] = 4;
        variants.push(wrong_acl_count);
        let mut trailing = original.clone();
        trailing.push(0);
        variants.push(trailing);
        variants.push(original[..original.len() - 1].to_vec());
        for (index, bytes) in variants.iter().enumerate() {
            assert!(
                parse_three_allowed_aces(bytes).is_err(),
                "malformed ACL variant {index} must deny"
            );
        }
    }
}
