//! Acquire the first capability without following a replaceable namespace alias.
//! Root path selection remains a trusted-policy responsibility; this module
//! rejects symlinks/junctions during acquisition, rather than authenticating policy.
use cap_std::fs::Dir;
use std::{
    io,
    path::{Component, Path},
};

fn reject() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Untrusted capability root")
}

fn validate_root(root: &Path) -> io::Result<()> {
    if !root.is_absolute()
        || root
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(reject());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn open_root_dir(raw: &str) -> io::Result<Dir> {
    use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
    let root = Path::new(raw);
    validate_root(root)?;
    // The kernel-owned filesystem root cannot be renamed by a namespace swap.
    let anchor = std::fs::File::open("/")?;
    let relative = root.strip_prefix("/").map_err(|_| reject())?;
    let relative = if relative.as_os_str().is_empty() {
        Path::new(".")
    } else {
        relative
    };
    // One atomic kernel resolution; no attacker-controlled intermediate links.
    // If openat2 is unavailable, fail closed instead of falling back to realpath.
    let fd = openat2(
        &anchor,
        relative,
        OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
    Ok(Dir::from_std_file(fd.into()))
}

#[cfg(windows)]
pub fn open_root_dir(raw: &str) -> io::Result<Dir> {
    use std::{
        fs::{File, OpenOptions},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::Prefix,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let root = Path::new(raw);
    validate_root(root)?;
    // Deny device, verbatim and drive-relative prefixes until separately audited.
    match root.components().next() {
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _)) =>
        {}
        _ => return Err(reject()),
    }
    let path_chain: Vec<_> = root.ancestors().filter(|p| p.has_root()).collect();
    let mut held: Vec<File> = Vec::with_capacity(path_chain.len());
    for prefix in path_chain.into_iter().rev() {
        // Holding each ancestor without FILE_SHARE_DELETE prevents rename of
        // any already-opened prefix during subsequent child acquisition.
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(prefix)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(reject());
        }
        held.push(file);
    }
    let root_file = held.pop().ok_or_else(reject)?;
    Ok(Dir::from_std_file(root_file))
}
#[cfg(not(any(windows, target_os = "linux")))]
pub fn open_root_dir(_raw: &str) -> io::Result<Dir> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Secure capability-root acquisition is unsupported on this OS",
    ))
}
