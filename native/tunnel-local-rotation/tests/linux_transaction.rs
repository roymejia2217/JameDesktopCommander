#![cfg(target_os = "linux")]
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use tempfile::TempDir;
use tunnel_local_rotation::{recover_local_file, LocalFileRotation, RecoveryOutcome};

const OLD: &[u8] = b"synthetic-old-runtime-token";
const NEW: &[u8] = b"synthetic-new-runtime-token";
struct Fixture(TempDir);
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("jdc-local-rotation-")
            .tempdir()
            .unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path().join("runtime.key"))
            .unwrap();
        f.write_all(OLD).unwrap();
        f.sync_all().unwrap();
        Self(dir)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.path().join("runtime.key")
    }
    fn clean(&self) {
        let names: Vec<_> = fs::read_dir(self.0.path())
            .unwrap()
            .map(|x| x.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names
                .iter()
                .all(|x| x == "runtime.key" || x == ".jdc-rot-lock"),
            "No lingering plaintext staging files or transaction journal"
        );
    }
}
#[test]
fn durable_commit_and_no_credential_echo() {
    let f = Fixture::new();
    let mut input = NEW.to_vec();
    let mut txn = LocalFileRotation::begin(&f.path(), &mut input).unwrap();
    assert!(input.iter().all(|b| *b == 0));
    assert_eq!(fs::read(f.path()).unwrap(), OLD);
    txn.publish().unwrap();
    assert_eq!(fs::read(f.path()).unwrap(), NEW);
    txn.confirm().unwrap();
    assert_eq!(fs::read(f.path()).unwrap(), NEW);
    assert_eq!(fs::metadata(f.path()).unwrap().mode() & 0o777, 0o600);
    f.clean();
}
#[test]
fn rollback_restores_old_inode_without_false_authentication() {
    let f = Fixture::new();
    let ino = fs::metadata(f.path()).unwrap().ino();
    let mut txn = LocalFileRotation::begin(&f.path(), &mut NEW.to_vec()).unwrap();
    txn.publish().unwrap();
    assert_eq!(fs::read(f.path()).unwrap(), NEW);
    txn.rollback().unwrap();
    assert_eq!(fs::read(f.path()).unwrap(), OLD);
    assert_eq!(fs::metadata(f.path()).unwrap().ino(), ino);
    f.clean();
}
#[test]
fn crash_after_publish_requires_and_supports_explicit_recovery() {
    let f = Fixture::new();
    {
        let mut txn = LocalFileRotation::begin(&f.path(), &mut NEW.to_vec()).unwrap();
        txn.publish().unwrap();
    }
    assert!(LocalFileRotation::begin(&f.path(), &mut NEW.to_vec()).is_err());
    assert_eq!(
        recover_local_file(&f.path()).unwrap(),
        RecoveryOutcome::PriorFileRestoredProviderUnverified
    );
    assert_eq!(fs::read(f.path()).unwrap(), OLD);
    f.clean();
}
#[test]
fn crash_before_publish_discards_staged_candidate() {
    let f = Fixture::new();
    {
        let _txn = LocalFileRotation::begin(&f.path(), &mut NEW.to_vec()).unwrap();
    }
    assert_eq!(
        recover_local_file(&f.path()).unwrap(),
        RecoveryOutcome::PriorFileRestoredProviderUnverified
    );
    assert_eq!(fs::read(f.path()).unwrap(), OLD);
    f.clean();
}
#[test]
fn exclusive_writer_lease_denies_concurrent_rotation() {
    let f = Fixture::new();
    let mut first = LocalFileRotation::begin(&f.path(), &mut NEW.to_vec()).unwrap();
    let error = LocalFileRotation::begin(&f.path(), &mut NEW.to_vec())
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "Local credential transaction denied.");
    first.rollback().unwrap();
}
#[test]
fn reject_insecure_permissions_hardlinks_and_symlink_targets() {
    let f = Fixture::new();
    let p = f.path();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(LocalFileRotation::begin(&p, &mut NEW.to_vec()).is_err());
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = f.0.path().join("alias");
    fs::hard_link(&p, &alias).unwrap();
    assert!(LocalFileRotation::begin(&p, &mut NEW.to_vec()).is_err());
    fs::remove_file(alias).unwrap();
    let backing = f.0.path().join("backing");
    fs::rename(&p, &backing).unwrap();
    std::os::unix::fs::symlink(&backing, &p).unwrap();
    assert!(LocalFileRotation::begin(&p, &mut NEW.to_vec()).is_err());
    fs::remove_file(&p).unwrap();
    fs::rename(backing, &p).unwrap();
    fs::set_permissions(f.0.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(LocalFileRotation::begin(&p, &mut NEW.to_vec()).is_err());
}
#[test]
fn fixed_errors_never_echo_path_or_secret_and_missing_target_denies() {
    let f = Fixture::new();
    let err = recover_local_file(&f.0.path().join("not-a-key"))
        .err()
        .unwrap();
    assert_eq!(err.to_string(), "Local credential transaction denied.");
    assert!(!err.to_string().contains("not-a-key"));
    assert!(LocalFileRotation::begin(&f.0.path().join("missing.key"), &mut NEW.to_vec()).is_err());
}

#[test]
fn recovery_rejects_different_filename_even_if_inode_was_moved() {
    let f = Fixture::new();
    let unrelated = f.0.path().join("unrelated.key");
    {
        let mut txn = LocalFileRotation::begin(&f.path(), &mut NEW.to_vec()).unwrap();
        txn.publish().unwrap();
    }
    fs::rename(f.path(), &unrelated).unwrap();
    assert!(
        recover_local_file(&unrelated).is_err(),
        "Transaction must remain bound to the original registered filename"
    );
    assert_eq!(fs::read(&unrelated).unwrap(), NEW);
    fs::rename(unrelated, f.path()).unwrap();
    assert_eq!(
        recover_local_file(&f.path()).unwrap(),
        RecoveryOutcome::PriorFileRestoredProviderUnverified
    );
    assert_eq!(fs::read(f.path()).unwrap(), OLD);
    f.clean();
}

#[test]
fn child_process_abrupt_exit_after_publish_exercises_real_kernel_lease_release() {
    const CHILD: &str = "child_process_crashes_during_publication_fixture";
    let f = Fixture::new();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(CHILD)
        .arg("--nocapture")
        .env("JDC_SYNTHETIC_ROTATION_TEST_FILE", f.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    assert_eq!(fs::read(f.path()).unwrap(), NEW);
    assert!(LocalFileRotation::begin(&f.path(), &mut NEW.to_vec()).is_err());
    assert_eq!(
        recover_local_file(&f.path()).unwrap(),
        RecoveryOutcome::PriorFileRestoredProviderUnverified
    );
    assert_eq!(fs::read(f.path()).unwrap(), OLD);
    f.clean();
}

#[test]
fn child_process_crashes_during_publication_fixture() {
    let Ok(path) = std::env::var("JDC_SYNTHETIC_ROTATION_TEST_FILE") else {
        return; // Parent integration suite must never rotate anything.
    };
    let synthetic = std::path::Path::new(&path);
    let parent = synthetic.parent().expect("disposable parent");
    assert_eq!(synthetic.file_name().unwrap(), "runtime.key");
    assert!(parent
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("jdc-local-rotation-"));
    assert_eq!(
        fs::read(synthetic).unwrap(),
        OLD,
        "Crash fixture may only alter an original synthetic test credential"
    );
    let mut txn =
        LocalFileRotation::begin(synthetic, &mut NEW.to_vec()).expect("disposable test file only");
    txn.publish().expect("publish synthetic test key");
    std::process::exit(73); // No destructors; emulates process loss.
}

#[test]
fn recovery_rejects_corrupted_journal_without_touching_published_credential() {
    let f = Fixture::new();
    {
        let mut txn = LocalFileRotation::begin(&f.path(), &mut NEW.to_vec()).unwrap();
        txn.publish().unwrap();
    }
    let journal_path = f.0.path().join(".jdc-rot-journal");
    let mut journal = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&journal_path)
        .unwrap();
    journal.write_all(b"malformed-publication-state").unwrap();
    journal.sync_all().unwrap();
    assert!(
        recover_local_file(&f.path()).is_err(),
        "Ambiguous journal must not guess or overwrite the published inode"
    );
    assert_eq!(fs::read(f.path()).unwrap(), NEW);
}

#[test]
fn committed_journal_recovery_retains_published_credential_not_expired_previous_key() {
    let f = Fixture::new();
    {
        let mut txn = LocalFileRotation::begin(&f.path(), &mut NEW.to_vec()).unwrap();
        txn.publish().unwrap();
    }
    let journal_path = f.0.path().join(".jdc-rot-journal");
    let state = fs::read_to_string(&journal_path).unwrap();
    assert!(state.contains("\nprepared\n"));
    // Emulates an abrupt exit just after the durable committed journal
    // record but before the cleanup of the private old-key stage.
    let committed = state.replacen("\nprepared\n", "\ncommitted\n", 1);
    let mut journal = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&journal_path)
        .unwrap();
    journal.write_all(committed.as_bytes()).unwrap();
    journal.sync_all().unwrap();
    assert_eq!(
        recover_local_file(&f.path()).unwrap(),
        RecoveryOutcome::ConfirmedCredentialRetainedProviderUnverified
    );
    assert_eq!(fs::read(f.path()).unwrap(), NEW);
    f.clean();
}

#[test]
fn file_target_name_cannot_contain_control_characters() {
    let f = Fixture::new();
    let invalid = f.0.path().join("token\tfile");
    let mut input = NEW.to_vec();
    assert!(LocalFileRotation::begin(&invalid, &mut input).is_err());
    assert!(input.iter().all(|byte| *byte == 0));
}

#[test]
fn separate_process_cannot_publish_or_recover_while_exclusive_lease_is_held() {
    const CHILD: &str = "child_process_competing_writer_fixture";
    let f = Fixture::new();
    let mut first = LocalFileRotation::begin(&f.path(), &mut NEW.to_vec()).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(CHILD)
        .arg("--nocapture")
        .env("JDC_SYNTHETIC_ROTATION_COMPETE_FILE", f.path())
        .status()
        .unwrap();
    assert!(status.success(), "A competing process must fail closed");
    assert_eq!(fs::read(f.path()).unwrap(), OLD);
    first.rollback().unwrap();
    f.clean();
}

#[test]
fn child_process_competing_writer_fixture() {
    let Ok(path) = std::env::var("JDC_SYNTHETIC_ROTATION_COMPETE_FILE") else {
        return;
    };
    let synthetic = std::path::Path::new(&path);
    assert_eq!(synthetic.file_name().unwrap(), "runtime.key");
    assert!(synthetic
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("jdc-local-rotation-"));
    assert_eq!(fs::read(synthetic).unwrap(), OLD);
    assert!(LocalFileRotation::begin(synthetic, &mut NEW.to_vec()).is_err());
    assert!(recover_local_file(synthetic).is_err());
    assert_eq!(fs::read(synthetic).unwrap(), OLD);
}
