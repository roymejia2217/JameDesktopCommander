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
        // Native in-place rewrite, retaining inode identity: this deliberately
        // exposes alias effects when both names belong to one file object.
        // Only a disposable security test probe; NOT a production writer.
        "rewrite" => {
            let replacement = fs::read(auxiliary)?;
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(protected)?
                .write_all(&replacement)
        }
        "hardlink" => fs::hard_link(protected, auxiliary),
        // CI-only identity proof; equal byte content is not evidence that two
        // Windows/Unix paths share the same OS file object.
        "same-object" => {
            if same_file::is_same_file(protected, auxiliary)? {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "different file objects",
                ))
            }
        }
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

// The acceptance runner must distinguish an actual OS permission denial
// from a missing source or another unrelated execution failure.
// Do not report paths, credentials or file bytes.
fn format_probe_os_error(mode: &str, error: &io::Error) -> String {
    let prefix = if mode == "hardlink" {
        "E_HARDLINK_OS_ERROR"
    } else {
        "E_PROBE_OS_ERROR"
    };
    format!("{prefix}_{}", error.raw_os_error().unwrap_or(-1))
}

#[cfg(test)]
mod tests {
    use super::attempt;
    use std::{fs, io};

    #[test]
    fn probe_error_contract_distinguishes_access_denial_from_missing_source() {
        let denied = io::Error::from_raw_os_error(5);
        let missing = io::Error::from_raw_os_error(2);
        assert_eq!(
            super::format_probe_os_error("read", &denied),
            "E_PROBE_OS_ERROR_5"
        );
        assert_eq!(
            super::format_probe_os_error("read", &missing),
            "E_PROBE_OS_ERROR_2"
        );
        assert_eq!(
            super::format_probe_os_error("hardlink", &denied),
            "E_HARDLINK_OS_ERROR_5"
        );
    }

    #[test]
    fn identical_bytes_do_not_prove_identical_file_objects() {
        let dir = tempfile::tempdir().expect("disposable isolated fixture");
        let source = dir.path().join("source.bin");
        let copied = dir.path().join("copied.bin");
        let hardlink = dir.path().join("alias.bin");
        fs::write(&source, b"EXACT SAME BYTES").expect("create original");
        fs::copy(&source, &copied).expect("make independent copy");
        attempt("hardlink", &source, &hardlink).expect("make real alias");
        assert!(
            attempt("same-object", &source, &hardlink).is_ok(),
            "real hard links must identify the same filesystem object"
        );
        assert!(
            attempt("same-object", &source, &copied).is_err(),
            "equal bytes from independent objects must not establish identity"
        );
    }

    #[test]
    fn rewrite_preserves_native_file_identity_and_reaches_all_hardlink_aliases() {
        let dir = tempfile::tempdir().expect("disposable private fixture");
        let source = dir.path().join("original.bin");
        let alias = dir.path().join("alias.bin");
        let replacement = dir.path().join("replacement.bin");
        fs::write(&source, b"ORIGINAL_BYTES").unwrap();
        fs::write(&replacement, b"REPLACED_BYTES").unwrap();
        attempt("hardlink", &source, &alias).unwrap();
        assert!(same_file::is_same_file(&source, &alias).unwrap());
        attempt("rewrite", &source, &replacement)
            .expect("rewrite probe must perform a real native in-place rewrite");
        assert_eq!(fs::read(&source).unwrap(), b"REPLACED_BYTES");
        assert_eq!(fs::read(&alias).unwrap(), b"REPLACED_BYTES");
        assert!(same_file::is_same_file(&source, &alias).unwrap());
    }

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
    match attempt(mode, Path::new(&db), Path::new(&aux)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // A generic failure is not evidence of a filesystem boundary.
            // Report only the OS code (no paths) so hosted acceptance can
            // require ERROR_NOT_SAME_DEVICE instead of unrelated ACL errors.
            eprintln!("{}", format_probe_os_error(mode, &error));
            ExitCode::FAILURE
        }
    }
}
