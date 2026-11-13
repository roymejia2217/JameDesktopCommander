//! Non-shipping Linux handle-relative regular-file read primitive.
//! The root handle must already be authenticated and retained by the future
//! authority process. This function does NOT authorize a root or a client.
//! #148 object origin, policy epoch and authenticated IPC remain unproven.
#[cfg(any(target_os = "linux", test))]
use std::path::{Component, Path};

#[cfg(any(target_os = "linux", test))]
pub(crate) fn validate_relative_name(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::Normal(_)))
        && components.all(|component| matches!(component, Component::Normal(_)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadDenied;

#[cfg(target_os = "linux")]
pub fn read_regular_at(root: &std::fs::File, relative: &Path) -> Result<Vec<u8>, ReadDenied> {
    use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
    use std::{fs::File, io::Read};
    const MAX_BYTES: usize = 1024 * 1024;

    if !validate_relative_name(relative) {
        return Err(ReadDenied);
    }
    if !root.metadata().map_err(|_| ReadDenied)?.is_dir() {
        return Err(ReadDenied);
    }
    // Reuse the established T011 kernel resolution contract. NO_XDEV
    // refuses imported bind mounts; it does not establish object origin.
    let fd = openat2(
        root,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| ReadDenied)?;
    let file = File::from(fd);
    if !file.metadata().map_err(|_| ReadDenied)?.is_file() {
        return Err(ReadDenied);
    }
    let mut data = Vec::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|_| ReadDenied)?;
    if data.len() > MAX_BYTES {
        return Err(ReadDenied);
    }
    Ok(data)
}
