#![cfg(target_os = "linux")]

use rustix::fs::{linkat, openat, AtFlags, Mode, OFlags};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use tempfile::tempdir;

// Research fixture only: procfs custody and mount topology are not attested.
fn open_unnamed_fixture(directory: &File) -> File {
    let fd = openat(
        directory,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("O_TMPFILE must be supported by the test filesystem");
    File::from(fd)
}

fn publish_unnamed_fixture(
    proc_fd: &File,
    source: &File,
    directory: &File,
    name: &str,
) -> std::io::Result<()> {
    linkat(
        proc_fd,
        source.as_raw_fd().to_string(),
        directory,
        name,
        AtFlags::SYMLINK_FOLLOW,
    )
    .map_err(Into::into)
}

fn publish_via_verified_proc_fixture(
    source: &File,
    directory: &File,
    name: &str,
) -> std::io::Result<()> {
    let proc_fd = rustix_linux_procfs::proc_self_fd().map_err(std::io::Error::from)?;
    linkat(
        proc_fd,
        source.as_raw_fd().to_string(),
        directory,
        name,
        AtFlags::SYMLINK_FOLLOW,
    )
    .map_err(Into::into)
}

fn assert_no_dac_read_search() {
    let status = fs::read_to_string("/proc/self/status").expect("read actual process capabilities");
    for field in ["CapPrm:", "CapEff:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .expect("process capability field")
            .trim();
        let mask = u64::from_str_radix(value, 16).expect("valid capability mask");
        assert_eq!(
            mask & (1 << 2),
            0,
            "fixture must not hold CAP_DAC_READ_SEARCH"
        );
    }
}

#[test]
fn unnamed_file_is_fully_written_before_handle_relative_publication() {
    assert_no_dac_read_search();
    let root = tempdir().unwrap();
    let destination = root.path().join("published.bin");
    let dir = File::open(root.path()).unwrap();
    let proc_fd = File::open("/proc/self/fd").unwrap();
    let mut source = open_unnamed_fixture(&dir);
    let payload = b"COMPLETE_UNNAMED_PAYLOAD";
    source.write_all(payload).unwrap();
    source.sync_all().unwrap();
    let original = source.metadata().unwrap();
    assert_eq!(
        original.nlink(),
        0,
        "source must have no name before publication"
    );
    assert!(!destination.exists());
    publish_unnamed_fixture(&proc_fd, &source, &dir, "published.bin").unwrap();
    let published = fs::metadata(&destination).unwrap();
    assert_eq!(
        (original.dev(), original.ino()),
        (published.dev(), published.ino())
    );
    assert_eq!(fs::read(&destination).unwrap(), payload);
}

#[test]
fn unnamed_publication_does_not_replace_existing_outside_alias() {
    assert_no_dac_read_search();
    let root = tempdir().unwrap();
    let allowed = root.path().join("allowed");
    fs::create_dir(&allowed).unwrap();
    let outside = root.path().join("outside.bin");
    let destination = allowed.join("occupied.bin");
    fs::write(&outside, b"OUTSIDE_ORIGINAL").unwrap();
    fs::hard_link(&outside, &destination).unwrap();
    let before = fs::metadata(&outside).unwrap();
    assert_eq!(before.ino(), fs::metadata(&destination).unwrap().ino());
    let dir = File::open(&allowed).unwrap();
    let proc_fd = File::open("/proc/self/fd").unwrap();
    let mut source = open_unnamed_fixture(&dir);
    source.write_all(b"PRIVATE_PAYLOAD").unwrap();
    source.sync_all().unwrap();
    let err = publish_unnamed_fixture(&proc_fd, &source, &dir, "occupied.bin").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&outside).unwrap(), b"OUTSIDE_ORIGINAL");
    assert_eq!(fs::metadata(&destination).unwrap().ino(), before.ino());
    assert_eq!(source.metadata().unwrap().nlink(), 0);
    source.seek(SeekFrom::Start(0)).unwrap();
    let mut source_bytes = Vec::new();
    source.read_to_end(&mut source_bytes).unwrap();
    assert_eq!(source_bytes, b"PRIVATE_PAYLOAD");
}

#[test]
fn negative_control_moved_destination_directory_exposes_published_bytes() {
    assert_no_dac_read_search();
    let root = tempdir().unwrap();
    let allowed = root.path().join("allowed");
    let outside = root.path().join("outside");
    fs::create_dir(&allowed).unwrap();
    fs::create_dir(&outside).unwrap();
    let dir = File::open(&allowed).unwrap();
    let proc_fd = File::open("/proc/self/fd").unwrap();
    let mut source = open_unnamed_fixture(&dir);
    let payload = b"PRIVATE_BEFORE_PARENT_MOVE";
    source.write_all(payload).unwrap();
    source.sync_all().unwrap();
    let original = source.metadata().unwrap();
    assert_eq!(original.nlink(), 0);

    // An attacker with parent-namespace write authority moves the pinned
    // directory outside the approved pathname before the publication call.
    let moved = outside.join("moved");
    fs::rename(&allowed, &moved).expect("attack must actually move the pinned directory");
    assert!(!allowed.exists());
    publish_unnamed_fixture(&proc_fd, &source, &dir, "published.bin")
        .expect("negative control must demonstrate the unguarded publication");
    let published = moved.join("published.bin");
    let meta = fs::metadata(&published).unwrap();
    assert_eq!((original.dev(), original.ino()), (meta.dev(), meta.ino()));
    assert_eq!(fs::read(published).unwrap(), payload);
}

#[test]
fn negative_control_same_principal_can_alias_published_object_outside_root() {
    assert_no_dac_read_search();
    let root = tempdir().unwrap();
    let allowed = root.path().join("allowed");
    let outside = root.path().join("outside");
    fs::create_dir(&allowed).unwrap();
    fs::create_dir(&outside).unwrap();
    let dir = File::open(&allowed).unwrap();
    let proc_fd = File::open("/proc/self/fd").unwrap();
    let mut source = open_unnamed_fixture(&dir);
    let payload = b"PUBLISHED_OBJECT_CONTENT";
    source.write_all(payload).unwrap();
    source.sync_all().unwrap();
    publish_unnamed_fixture(&proc_fd, &source, &dir, "published.bin").unwrap();
    let alias = outside.join("alias.bin");
    fs::hard_link(allowed.join("published.bin"), &alias)
        .expect("attack must create a real exterior alias");
    let original = source.metadata().unwrap();
    let linked = fs::metadata(&alias).unwrap();
    assert_eq!(
        (original.dev(), original.ino()),
        (linked.dev(), linked.ino())
    );
    assert_eq!(fs::read(alias).unwrap(), payload);
}

#[test]
fn negative_control_untrusted_proc_directory_substitutes_source_object() {
    assert_no_dac_read_search();
    let root = tempdir().unwrap();
    let allowed = root.path().join("allowed");
    let fake_proc = root.path().join("fake-proc-fd");
    fs::create_dir(&allowed).unwrap();
    fs::create_dir(&fake_proc).unwrap();
    let dir = File::open(&allowed).unwrap();
    let mut source = open_unnamed_fixture(&dir);
    source.write_all(b"APPROVED_PAYLOAD").unwrap();
    source.sync_all().unwrap();
    let original = source.metadata().unwrap();
    let forged = fake_proc.join(source.as_raw_fd().to_string());
    fs::write(&forged, b"ATTACKER_PAYLOAD").unwrap();
    let forged_meta = fs::metadata(&forged).unwrap();
    assert_ne!(
        (original.dev(), original.ino()),
        (forged_meta.dev(), forged_meta.ino())
    );

    // Replacing the procfs directory handle with an untrusted ordinary
    // directory makes the same relative lookup select the attacker's object.
    let fake_proc_fd = File::open(&fake_proc).unwrap();
    publish_unnamed_fixture(&fake_proc_fd, &source, &dir, "published.bin")
        .expect("negative control must publish the substituted object");
    let published = allowed.join("published.bin");
    let actual = fs::metadata(&published).unwrap();
    assert_eq!(
        (actual.dev(), actual.ino()),
        (forged_meta.dev(), forged_meta.ino())
    );
    assert_eq!(fs::read(published).unwrap(), b"ATTACKER_PAYLOAD");
    assert_eq!(source.metadata().unwrap().nlink(), 0);
}

#[test]
fn verified_proc_fixture_publishes_original_despite_forged_fd_directory() {
    assert_no_dac_read_search();
    let root = tempdir().unwrap();
    let allowed = root.path().join("allowed");
    let fake_proc = root.path().join("fake-proc-fd");
    fs::create_dir(&allowed).unwrap();
    fs::create_dir(&fake_proc).unwrap();
    let dir = File::open(&allowed).unwrap();
    let mut source = open_unnamed_fixture(&dir);
    source.write_all(b"APPROVED_PAYLOAD").unwrap();
    source.sync_all().unwrap();
    let original = source.metadata().unwrap();
    let forged = fake_proc.join(source.as_raw_fd().to_string());
    fs::write(&forged, b"ATTACKER_PAYLOAD").unwrap();

    publish_via_verified_proc_fixture(&source, &dir, "published.bin")
        .expect("verified procfs publication must use the opened source");
    let published = allowed.join("published.bin");
    let actual = fs::metadata(&published).unwrap();
    assert_eq!(
        (actual.dev(), actual.ino()),
        (original.dev(), original.ino())
    );
    assert_eq!(fs::read(published).unwrap(), b"APPROVED_PAYLOAD");
    assert_eq!(fs::read(forged).unwrap(), b"ATTACKER_PAYLOAD");
}
