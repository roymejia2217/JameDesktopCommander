//! Canonical epoch+SHA-256 witness wire contract shared across platforms.
//! This is data integrity only, not policy publisher authentication.
use crate::IdentityDenied;

pub(crate) fn parse_epoch_digest_wire(bytes: &[u8]) -> Result<(u64, [u8; 32]), IdentityDenied> {
    let array: [u8; 40] = bytes.try_into().map_err(|_| IdentityDenied)?;
    let epoch = u64::from_be_bytes(array[..8].try_into().map_err(|_| IdentityDenied)?);
    let digest: [u8; 32] = array[8..].try_into().map_err(|_| IdentityDenied)?;
    if epoch == 0 || digest == [0; 32] {
        return Err(IdentityDenied);
    }
    Ok((epoch, digest))
}

#[cfg(test)]
mod tests {
    use super::parse_epoch_digest_wire;

    #[test]
    fn rejects_empty_zero_epoch_zero_digest_and_trailing_bytes() {
        assert!(parse_epoch_digest_wire(&[]).is_err());
        let mut value = [0u8; 40];
        value[8] = 1;
        assert!(parse_epoch_digest_wire(&value).is_err());
        value[7] = 1;
        value[8] = 0;
        assert!(parse_epoch_digest_wire(&value).is_err());
        value[8] = 2;
        assert!(parse_epoch_digest_wire(&[value.as_slice(), &[0]].concat()).is_err());
        assert!(parse_epoch_digest_wire(&value[..39]).is_err());
    }

    #[test]
    fn accepts_big_endian_epoch_and_exact_digest() {
        let mut value = [0u8; 40];
        value[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        value[8..].fill(0xA5);
        assert_eq!(parse_epoch_digest_wire(&value), Ok((u64::MAX, [0xA5; 32])));
    }
}
