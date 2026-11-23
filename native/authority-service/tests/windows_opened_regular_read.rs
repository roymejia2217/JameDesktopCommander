#![cfg(windows)]
// Real NTFS-backed tests: reads never reopen a previously validated pathname.
use jdc_authority_service::windows_opened_read::read_opened_regular;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct TempFile(PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn owned_file(bytes: &[u8]) -> (TempFile, File) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let unique = SERIAL.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "jdc-opened-read-{}-{now}-{unique}.bin",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("real readable file");
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    (TempFile(path), file)
}

#[test]
fn binary_read_uses_only_the_preopened_file_object() {
    let bytes = [0, 255, 129, 42, 10];
    let (_file, mut handle) = owned_file(&bytes);
    let mut prefix = [0; 2];
    handle.read_exact(&mut prefix).unwrap();
    assert_eq!(read_opened_regular(handle), Ok(bytes.to_vec()));
}

#[test]
fn rejects_oversized_opened_file_without_returning_partial_bytes() {
    let (_path, file) = owned_file(b"hidden");
    file.set_len(1024 * 1024 + 1).unwrap();
    assert!(read_opened_regular(file).is_err());
}

#[test]
fn rejects_an_existing_second_hardlink_to_the_same_object() {
    let (source, file) = owned_file(b"SERVICE_DOMAIN");
    let alias = source.0.with_extension("alias");
    fs::hard_link(&source.0, &alias).expect("real same-volume hardlink");
    let _alias_cleanup = TempFile(alias);
    assert!(
        read_opened_regular(file).is_err(),
        "an object with multiple names cannot be admitted from path confinement alone"
    );
}

#[test]
fn a_replaced_filename_does_not_change_the_original_open_file_bytes() {
    let (original, retained) = owned_file(b"ORIGINAL_OBJECT");
    let renamed = original.0.with_extension("moved");
    fs::rename(&original.0, &renamed).expect("open handle permits name replacement");
    let _renamed_cleanup = TempFile(renamed);
    fs::write(&original.0, b"HOSTILE_REPLACEMENT").expect("independent name now exists");
    let _replacement_cleanup = TempFile(original.0.clone());

    assert_eq!(
        read_opened_regular(retained),
        Ok(b"ORIGINAL_OBJECT".to_vec()),
        "the read must follow its retained native HANDLE, not the substituted path"
    );
}

#[test]
fn accepts_exactly_the_size_limit_and_an_empty_regular_file() {
    let (_empty_path, empty) = owned_file(b"");
    assert_eq!(read_opened_regular(empty), Ok(Vec::new()));

    let (_max_path, max) = owned_file(b"");
    max.set_len(1024 * 1024).unwrap();
    let bytes = read_opened_regular(max).expect("exactly the maximum is valid");
    assert_eq!(bytes.len(), 1024 * 1024);
    assert!(bytes.iter().all(|&b| b == 0));
}
