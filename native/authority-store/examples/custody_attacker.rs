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
        "hardlink" => fs::hard_link(protected, auxiliary),
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

#[cfg(test)]
mod tests {
    use super::attempt;
    use std::fs;

    #[test]
    fn hardlink_probe_proves_positive_identity_and_denies_missing_source() {
        let dir = tempfile::tempdir().expect("disposable private fixture");
        let source = dir.path().join("own-source.bin");
        let link = dir.path().join("own-hardlink.bin");
        fs::write(&source, b"UNCHANGED").expect("create source");
        attempt("hardlink", &source, &link).expect("own hardlink must work");
        let source_meta = fs::metadata(&source).expect("source metadata");
        let alias_meta = fs::metadata(&link).expect("alias metadata");
        assert_eq!(source_meta.len(), alias_meta.len());
        assert_eq!(fs::read(&link).expect("alias content"), b"UNCHANGED");
        assert!(attempt(
            "hardlink",
            &dir.path().join("absent"),
            &dir.path().join("new")
        )
        .is_err());
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
