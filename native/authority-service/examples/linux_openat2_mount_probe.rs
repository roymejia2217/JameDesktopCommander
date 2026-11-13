//! Test-only Linux kernel path-resolution probe; not a service grant or shipped binary.
#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use jdc_authority_service::confined_read::read_regular_at;
    use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
    use std::{
        env,
        fs::File,
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
        (Some("allow"), Ok(_)) => match read_regular_at(&root_dir, name) {
            Ok(bytes) if bytes == b"SERVICE_DOMAIN_BYTES" => ExitCode::SUCCESS,
            _ => {
                eprintln!("E_OPENAT2_AUTHORIZED_READ_MISMATCH");
                ExitCode::FAILURE
            }
        },
        (Some("allow-limit"), Ok(_)) => match read_regular_at(&root_dir, name) {
            Ok(bytes) if bytes.len() == 1048576 && bytes.iter().all(|&b| b == 0) => {
                ExitCode::SUCCESS
            }
            _ => {
                eprintln!("E_OPENAT2_READ_LIMIT_MISMATCH");
                ExitCode::FAILURE
            }
        },
        (Some("deny"), _) if read_regular_at(&root_dir, name).is_err() => ExitCode::SUCCESS,
        (Some("deny"), _) => {
            eprintln!("E_OPENAT2_UNEXPECTED_READ_PERMISSION");
            ExitCode::FAILURE
        }
        (Some("deny-exdev"), Err(error))
            if error.raw_os_error() == libc::EXDEV && read_regular_at(&root_dir, name).is_err() =>
        {
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
