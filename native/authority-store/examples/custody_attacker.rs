//! Test-only NTFS file-operation probes for a separate unprivileged SID.
//! Runs on an ephemeral Windows GitHub runner; never used for runtime grants.
use std::{
    env, fs,
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

fn attempt(mode: &str, protected: &Path, auxiliary: &Path) -> io::Result<()> {
    match mode {
        "canary" => fs::write(auxiliary, b"ordinary account can write own file"),
        "read" => fs::read(protected).map(|_| ()),
        "append" => OpenOptions::new()
            .append(true)
            .open(protected)?
            .write_all(b"unauthorized"),
        "overwrite" => fs::copy(auxiliary, protected).map(|_| ()),
        "rename" => fs::rename(protected, protected.with_extension("renamed")),
        "unlink" => fs::remove_file(protected),
        "create" => fs::write(
            protected.parent().unwrap().join("forged.sqlite3"),
            b"forged",
        ),
        "parent-rename" => fs::rename(
            protected.parent().unwrap(),
            protected.parent().unwrap().with_extension("moved"),
        ),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown operation",
        )),
    }
}

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let (Some(mode), Some(db), Some(aux), None) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        return ExitCode::FAILURE;
    };
    let Some(mode) = mode.to_str() else {
        return ExitCode::FAILURE;
    };
    if attempt(mode, Path::new(&db), Path::new(&aux)).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
