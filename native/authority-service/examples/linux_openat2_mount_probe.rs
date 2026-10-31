//! Test-only Linux kernel path-resolution probe; not a service grant or shipped binary.
#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
    use std::{
        env,
        fs::File,
        io::Read,
        path::{Component, Path},
        process::ExitCode,
    };

    let mut args = env::args_os().skip(1);
    let (Some(root), Some(relative), Some(mode), None) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        eprintln!("E_OPENAT2_PROBE_ARGS");
        return ExitCode::FAILURE;
    };

    let name = Path::new(&relative);
    if name.is_absolute()
        || !name
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        eprintln!("E_OPENAT2_PROBE_RELATIVE_NAME");
        return ExitCode::FAILURE;
    }
    let root_dir = match File::open(root) {
        Ok(root_dir) => root_dir,
        Err(error) => {
            eprintln!("E_OPENAT2_ROOT_OPEN: {error}");
            return ExitCode::FAILURE;
        }
    };
    let observed = openat2(
        &root_dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    );
    match (mode.to_str(), observed) {
        (Some("allow"), Ok(fd)) => {
            let file = File::from(fd);
            let mut bytes = Vec::new();
            match file.take(64).read_to_end(&mut bytes) {
                Ok(_) if bytes == b"SERVICE_DOMAIN_BYTES" => ExitCode::SUCCESS,
                _ => {
                    eprintln!("E_OPENAT2_AUTHORIZED_READ_MISMATCH");
                    ExitCode::FAILURE
                }
            }
        }
        (Some("deny-exdev"), Err(error)) if error.raw_os_error() == libc::EXDEV => {
            ExitCode::SUCCESS
        }
        (Some("deny-exdev"), Err(error)) => {
            eprintln!("E_OPENAT2_WRONG_DENIAL: {}", error.raw_os_error());
            ExitCode::FAILURE
        }
        (Some("deny-exdev"), Ok(_)) => {
            eprintln!("E_OPENAT2_BIND_ALIAS_ACCEPTED");
            ExitCode::FAILURE
        }
        _ => {
            eprintln!("E_OPENAT2_UNEXPECTED_RESULT");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("E_OPENAT2_LINUX_ONLY");
    std::process::ExitCode::FAILURE
}
