//! Pure bounded parser for a Windows self-relative security descriptor.
//! All input is owned bytes; no native pointers or file names enter here.

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

fn bounded_sid(bytes: &[u8], at: usize) -> Option<&[u8]> {
    let head = bytes.get(at..at.checked_add(8)?)?;
    if head[0] != 1 || !(1..=15).contains(&head[1]) {
        return None;
    }
    let len = 8usize.checked_add(usize::from(head[1]).checked_mul(4)?)?;
    bytes.get(at..at.checked_add(len)?)
}

fn known_principal(sid: &[u8], user: &[u8], system: &[u8], admins: &[u8]) -> bool {
    sid == user || sid == system || sid == admins
}

/// Inspect a bounded, owned, self-relative descriptor from the Windows API.
/// Return false unless every named ALLOW entry belongs to a known principal.
/// This is not an AccessCheck, authorization grant, or revocation guarantee.
pub(crate) fn private_acl(bytes: &[u8], user: &[u8], system: &[u8], admins: &[u8]) -> bool {
    if !(20..=32768).contains(&bytes.len()) || bytes[0] != 1 {
        return false;
    }
    let Some(flags) = le_u16(bytes, 2) else {
        return false;
    };
    // SECURITY_DESCRIPTOR_RELATIVE control: SELF_RELATIVE | DACL_PRESENT.
    if flags & 0x8004 != 0x8004 {
        return false;
    }
    let (Some(owner), Some(dacl)) = (le_u32(bytes, 4), le_u32(bytes, 16)) else {
        return false;
    };
    let (owner, dacl) = (owner as usize, dacl as usize);
    if owner < 20 || dacl < 20 {
        return false;
    }
    let Some(owner_sid) = bounded_sid(bytes, owner) else {
        return false;
    };
    if !known_principal(owner_sid, user, system, admins) {
        return false;
    }

    let Some(acl_head) = bytes.get(dacl..dacl.saturating_add(8)) else {
        return false;
    };
    if !matches!(acl_head[0], 2 | 4) {
        return false;
    }
    let (Some(acl_len), Some(ace_count)) = (le_u16(acl_head, 2), le_u16(acl_head, 4)) else {
        return false;
    };
    let acl_len = usize::from(acl_len);
    if !(8..=8192).contains(&acl_len) || ace_count > 64 {
        return false;
    }
    let Some(acl_end) = dacl.checked_add(acl_len) else {
        return false;
    };
    let Some(acl) = bytes.get(dacl..acl_end) else {
        return false;
    };
    let Some(owner_end) = owner.checked_add(owner_sid.len()) else {
        return false;
    };
    if owner < acl_end && dacl < owner_end {
        return false;
    }
    let mut cursor = 8usize;
    for _ in 0..ace_count {
        let Some(header) = acl.get(cursor..cursor.saturating_add(4)) else {
            return false;
        };
        let (kind, Some(size)) = (header[0], le_u16(header, 2)) else {
            return false;
        };
        let size = usize::from(size);
        if !matches!(kind, 0 | 1) || !(20..=8192).contains(&size) {
            return false;
        }
        let Some(end) = cursor.checked_add(size) else {
            return false;
        };
        let Some(ace) = acl.get(cursor..end) else {
            return false;
        };
        let Some(sid) = bounded_sid(ace, 8) else {
            return false;
        };
        if 8 + sid.len() != ace.len() {
            return false;
        }
        if kind == 0 && !known_principal(sid, user, system, admins) {
            return false;
        }
        cursor = end;
    }
    // ACL padding is acceptable only when it carries no hidden data.
    acl.get(cursor..)
        .is_some_and(|remaining| remaining.iter().all(|byte| *byte == 0))
}

#[cfg(test)]
mod tests {
    use super::private_acl;

    fn sid(rid: u32) -> Vec<u8> {
        let mut value = vec![1, 1, 0, 0, 0, 0, 0, 5];
        value.extend_from_slice(&rid.to_le_bytes());
        value
    }

    fn descriptor(owner: &[u8], grantee: &[u8]) -> Vec<u8> {
        let ace_size = 8 + grantee.len();
        let acl_size = 8 + ace_size;
        let mut out = vec![0u8; 20];
        out[0] = 1; // descriptor revision
        out[2..4].copy_from_slice(&0x8004u16.to_le_bytes()); // SR | DACL_PRESENT
        out[4..8].copy_from_slice(&20u32.to_le_bytes());
        out[16..20].copy_from_slice(&((20 + owner.len()) as u32).to_le_bytes());
        out.extend_from_slice(owner);
        let mut acl = vec![2, 0, 0, 0, 1, 0, 0, 0];
        acl[2..4].copy_from_slice(&(acl_size as u16).to_le_bytes());
        let mut ace = vec![0u8, 0, 0, 0, 0xff, 0, 0, 0];
        ace[2..4].copy_from_slice(&(ace_size as u16).to_le_bytes());
        ace.extend_from_slice(grantee);
        acl.extend_from_slice(&ace);
        out.extend_from_slice(&acl);
        out
    }

    #[test]
    fn valid_private_self_relative_descriptor_is_observed() {
        let user = sid(1001);
        let system = sid(18);
        let admins = sid(544);
        assert!(private_acl(
            &descriptor(&user, &user),
            &user,
            &system,
            &admins
        ));
    }

    #[test]
    fn a_foreign_allow_entry_is_not_private() {
        let user = sid(1001);
        let system = sid(18);
        let admins = sid(544);
        assert!(!private_acl(
            &descriptor(&user, &sid(2002)),
            &user,
            &system,
            &admins
        ));
    }
    #[test]
    fn null_dacl_and_truncated_data_fail_closed() {
        let user = sid(1001);
        let system = sid(18);
        let admins = sid(544);
        let mut input = descriptor(&user, &user);
        input[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert!(!private_acl(&input, &user, &system, &admins));
        let mut input = descriptor(&user, &user);
        for n in [0, 4, 19, 23, input.len() - 1] {
            input.truncate(n);
            assert!(!private_acl(&input, &user, &system, &admins));
            input = descriptor(&user, &user);
        }
    }

    #[test]
    fn every_truncation_of_valid_descriptor_is_denied() {
        let user = sid(1001);
        let system = sid(18);
        let admins = sid(544);
        let descriptor = descriptor(&user, &user);
        for count in 0..descriptor.len() {
            assert!(
                !private_acl(&descriptor[..count], &user, &system, &admins),
                "truncated descriptor must be denied at length {count}"
            );
        }
    }

    #[test]
    fn corrupt_acl_offsets_and_unknown_ace_type_fail_closed() {
        let user = sid(1001);
        let system = sid(18);
        let admins = sid(544);
        let mut input = descriptor(&user, &user);
        input[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!private_acl(&input, &user, &system, &admins));
        let mut input = descriptor(&user, &user);
        let acl_offset = 20 + user.len();
        input[acl_offset + 8] = 7; // unknown ACE type
        assert!(!private_acl(&input, &user, &system, &admins));
        let mut input = descriptor(&user, &user);
        input[acl_offset + 10..acl_offset + 12].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(!private_acl(&input, &user, &system, &admins));
    }
}
