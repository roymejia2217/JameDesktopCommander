//! Shared structural gate for a kernel-observed inherited socket descriptor.
//! Shape is NEVER sufficient to prove systemd provenance or grant authority.
use crate::IdentityDenied;

pub(crate) fn validate_listener_shape(
    domain: i32,
    socket_type: i32,
    accepting: i32,
    named: bool,
    path_matches: bool,
) -> Result<(), IdentityDenied> {
    // Numerical ABI constants are AF_UNIX=1, SOCK_STREAM=1 for Linux;
    // the caller must supply values obtained directly from the kernel.
    if domain != 1 || socket_type != 1 || accepting != 1 || !named || !path_matches {
        return Err(IdentityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_named_listening_unix_stream_passes_structural_gate() {
        assert_eq!(validate_listener_shape(1, 1, 1, true, true), Ok(()));
        for (domain, kind, accepting, named, same_path) in [
            (2, 1, 1, true, true),
            (1, 2, 1, true, true),
            (1, 1, 0, true, true),
            (1, 1, 1, false, true),
            (1, 1, 1, true, false),
            (0, 1, 1, true, true),
            (1, 0, 1, true, true),
            (1, 1, -1, true, true),
        ] {
            assert_eq!(
                validate_listener_shape(domain, kind, accepting, named, same_path),
                Err(IdentityDenied),
                "a different descriptor shape must fail closed",
            );
        }
    }
}
