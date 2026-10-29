//! Bounded Windows ACL decoding. Never interpret GetAce pointers as Rust references.
//! The final reader must constrain all relative offsets within the copied
//! GetSecurityInfo self-relative security descriptor.
use crate::IdentityDenied;

pub(crate) struct AllowedAce {
    pub(crate) sid: Vec<u8>,
    pub(crate) mask: u32,
    pub(crate) flags: u8,
}

// TDD RED: a fail-closed placeholder demonstrates that positive well-formed
// ACL data cannot yet be decoded. Replace only after verifying the test fails.
pub(crate) fn parse_three_allowed_aces(_raw: &[u8]) -> Result<Vec<AllowedAce>, IdentityDenied> {
    Err(IdentityDenied)
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
