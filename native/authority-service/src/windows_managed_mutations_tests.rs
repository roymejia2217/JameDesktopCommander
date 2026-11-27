//! Real Windows NTFS tests, isolated ordinary-user directory. Not admission proof.
use super::*;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        // Windows clock precision does not guarantee unique adjacent timestamps.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "jdc-win-mutation-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn domain(&self) -> Domain {
        Domain::new_fixture(&self.0, 1).unwrap()
    }
    fn bytes(&self, name: &str) -> Vec<u8> {
        fs::read(self.0.join(name)).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(d: &Domain, operation: Operation<'_>) -> Result<(), MutationError> {
    d.execute(
        &d.issue().unwrap(),
        operation,
        &AtomicBool::new(false),
        || {},
    )
}

#[test]
fn real_create_append_rewrite_rename_and_collision() {
    let f = Fixture::new();
    let d = f.domain();
    assert!(Domain::new_fixture(&f.0, 1).is_err());
    run(
        &d,
        Operation::Create {
            name: "a",
            bytes: b"one",
        },
    )
    .unwrap();
    let original = identity(&read_target(&d.root, "a").unwrap()).unwrap();
    assert_eq!(
        run(
            &d,
            Operation::Create {
                name: "A",
                bytes: b"other"
            }
        ),
        Err(MutationError::Collision)
    );
    assert_eq!(
        identity(&read_target(&d.root, "a").unwrap()).unwrap(),
        original
    );
    assert_eq!(f.bytes("a"), b"one");
    run(
        &d,
        Operation::Append {
            name: "a",
            bytes: &[0, 255],
        },
    )
    .unwrap();
    assert_eq!(f.bytes("a"), b"one\0\xff");
    run(
        &d,
        Operation::Rewrite {
            name: "a",
            bytes: b"replacement",
        },
    )
    .unwrap();
    let before = identity(&read_target(&d.root, "a").unwrap()).unwrap();
    run(&d, Operation::Rename { from: "a", to: "b" }).unwrap();
    assert_eq!(
        identity(&read_target(&d.root, "b").unwrap()).unwrap(),
        before
    );
    assert!(!f.0.join("a").exists());
    assert_eq!(f.bytes("b"), b"replacement");
    run(
        &d,
        Operation::Create {
            name: "a",
            bytes: b"another",
        },
    )
    .unwrap();
    assert_eq!(
        run(&d, Operation::Rename { from: "a", to: "b" }),
        Err(MutationError::Collision)
    );
    assert_eq!(f.bytes("a"), b"another");
    assert_eq!(f.bytes("b"), b"replacement");
}

#[test]
fn real_hardlink_alias_preserves_outside_and_invalid_names_deny() {
    let f = Fixture::new();
    let outside = Fixture::new();
    fs::write(outside.0.join("sentinel"), b"OUTSIDE").unwrap();
    fs::hard_link(outside.0.join("sentinel"), f.0.join("alias")).unwrap();
    assert_eq!(
        identity(&File::open(f.0.join("alias")).unwrap()).unwrap(),
        identity(&File::open(outside.0.join("sentinel")).unwrap()).unwrap()
    );
    assert_eq!(f.bytes("alias"), b"OUTSIDE");
    assert_eq!(
        info(&File::open(f.0.join("alias")).unwrap())
            .unwrap()
            .nNumberOfLinks,
        2
    );
    let d = f.domain();
    for name in ["alias", "../sentinel", "a:stream", "CON", ".jdc-stage"] {
        assert_eq!(
            run(&d, Operation::Append { name, bytes: b"x" }),
            Err(MutationError::Denied)
        );
        assert_eq!(
            run(&d, Operation::Rewrite { name, bytes: b"x" }),
            Err(MutationError::Denied)
        );
        assert_eq!(
            run(
                &d,
                Operation::Rename {
                    from: name,
                    to: "moved"
                }
            ),
            Err(MutationError::Denied)
        );
        assert_eq!(outside.bytes("sentinel"), b"OUTSIDE");
    }
    assert!(!f.0.join("moved").exists());
}

#[test]
fn revocation_and_cancellation_after_staging_prevent_commit() {
    for revoke in [true, false] {
        let f = Fixture::new();
        let d = f.domain();
        run(
            &d,
            Operation::Create {
                name: "a",
                bytes: b"before",
            },
        )
        .unwrap();
        let ticket = d.issue().unwrap();
        let cancelled = AtomicBool::new(false);
        assert_eq!(
            d.execute(
                &ticket,
                Operation::Append {
                    name: "a",
                    bytes: b"after"
                },
                &cancelled,
                || {
                    // The private stage is held exclusively; do not reopen it.
                    assert_eq!(f.bytes("a"), b"before");
                    if revoke {
                        d.policy.revoke().unwrap();
                    } else {
                        cancelled.store(true, Ordering::Release);
                    }
                }
            ),
            Err(MutationError::Denied)
        );
        assert_eq!(f.bytes("a"), b"before");
        assert!(!f.0.join(STAGE).exists());
    }
}

#[test]
fn bounded_append_serializes_and_leftover_stage_blocks_reopen() {
    let f = Fixture::new();
    let d = f.domain();
    run(
        &d,
        Operation::Create {
            name: "a",
            bytes: b"start",
        },
    )
    .unwrap();
    std::thread::scope(|s| {
        let a = s.spawn(|| {
            run(
                &d,
                Operation::Append {
                    name: "a",
                    bytes: b"A",
                },
            )
        });
        let b = s.spawn(|| {
            run(
                &d,
                Operation::Append {
                    name: "a",
                    bytes: b"B",
                },
            )
        });
        a.join().unwrap().unwrap();
        b.join().unwrap().unwrap();
    });
    let bytes = f.bytes("a");
    assert!(bytes == b"startAB" || bytes == b"startBA");
    assert_eq!(
        run(
            &d,
            Operation::Append {
                name: "a",
                bytes: &vec![0; MAX_BYTES]
            }
        ),
        Err(MutationError::Denied)
    );
    assert_eq!(f.bytes("a"), bytes);
    drop(d);
    fs::write(f.0.join(STAGE), b"orphan").unwrap();
    let reopened = f.domain();
    assert_eq!(
        run(
            &reopened,
            Operation::Rewrite {
                name: "a",
                bytes: b"next"
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
    assert_eq!(f.bytes(STAGE), b"orphan");
    assert_eq!(f.bytes("a"), bytes);
}

#[test]
fn staged_handle_blocks_substitution_before_commit() {
    let f = Fixture::new();
    let d = f.domain();
    run(
        &d,
        Operation::Create {
            name: "a",
            bytes: b"before",
        },
    )
    .unwrap();
    fs::write(f.0.join("control"), b"CONTROL").unwrap();
    let ticket = d.issue().unwrap();
    assert_eq!(
        d.execute(
            &ticket,
            Operation::Rewrite {
                name: "a",
                bytes: b"after"
            },
            &AtomicBool::new(false),
            || {
                fs::rename(f.0.join("control"), f.0.join("control-renamed")).unwrap();
                assert_eq!(f.bytes("control-renamed"), b"CONTROL");
                let err = fs::rename(f.0.join(STAGE), f.0.join("displaced")).unwrap_err();
                assert!(matches!(err.raw_os_error(), Some(5 | 32)), "{err}");
                assert!(!f.0.join("displaced").exists());
                assert_eq!(f.bytes("a"), b"before");
            }
        ),
        Ok(())
    );
    assert_eq!(f.bytes("a"), b"after");
    assert!(!f.0.join(STAGE).exists());
}

#[test]
fn replaced_destination_is_not_published_over() {
    let f = Fixture::new();
    let d = f.domain();
    run(
        &d,
        Operation::Create {
            name: "a",
            bytes: b"before",
        },
    )
    .unwrap();
    let ticket = d.issue().unwrap();
    assert_eq!(
        d.execute(
            &ticket,
            Operation::Rewrite {
                name: "a",
                bytes: b"new"
            },
            &AtomicBool::new(false),
            || {
                fs::rename(f.0.join("a"), f.0.join("original")).unwrap();
                fs::write(f.0.join("a"), b"replacement").unwrap();
            }
        ),
        Err(MutationError::Denied)
    );
    assert_eq!(f.bytes("a"), b"replacement");
    assert_eq!(f.bytes("original"), b"before");
    assert!(!f.0.join(STAGE).exists());
}

#[test]
fn hardlink_substitution_during_rewrite_preserves_outside_object() {
    let f = Fixture::new();
    let outside = Fixture::new();
    let sentinel = outside.0.join("sentinel");
    fs::write(&sentinel, b"OUTSIDE").unwrap();
    let original_identity = identity(&File::open(&sentinel).unwrap()).unwrap();
    let d = f.domain();
    run(
        &d,
        Operation::Create {
            name: "a",
            bytes: b"before",
        },
    )
    .unwrap();
    let ticket = d.issue().unwrap();
    let result = d.execute(
        &ticket,
        Operation::Rewrite {
            name: "a",
            bytes: b"new",
        },
        &AtomicBool::new(false),
        || {
            fs::rename(f.0.join("a"), f.0.join("original")).unwrap();
            fs::hard_link(&sentinel, f.0.join("a")).unwrap();
            let alias = File::open(f.0.join("a")).unwrap();
            assert_eq!(identity(&alias).unwrap(), original_identity);
            assert_eq!(info(&alias).unwrap().nNumberOfLinks, 2);
            assert_eq!(f.bytes("a"), b"OUTSIDE");
        },
    );
    assert_eq!(outside.bytes("sentinel"), b"OUTSIDE");
    assert_eq!(
        identity(&File::open(&sentinel).unwrap()).unwrap(),
        original_identity
    );
    assert_eq!(f.bytes("a"), b"OUTSIDE");
    assert_eq!(
        identity(&File::open(f.0.join("a")).unwrap()).unwrap(),
        original_identity
    );
    assert_eq!(f.bytes("original"), b"before");
    assert!(!f.0.join(STAGE).exists());
    assert_eq!(result, Err(MutationError::Denied));
}

#[derive(Clone, Copy)]
enum Fault {
    BeforeRename,
    AfterRename,
    StageWrite,
    StageSync,
    Cleanup,
    PublishSync,
}
struct FaultIo(Fault);
impl NativeIo for FaultIo {
    fn rename(&self, root: &File, source: &File, to: &str, replace: bool) -> Result<(), NTSTATUS> {
        use windows_sys::Win32::Foundation::STATUS_IO_DEVICE_ERROR;
        if matches!(self.0, Fault::BeforeRename) {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
        SystemIo.rename(root, source, to, replace)?;
        if matches!(self.0, Fault::AfterRename) {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
        Ok(())
    }
    fn write_stage(&self, file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
        if matches!(self.0, Fault::StageWrite) {
            file.write_all(&bytes[..1])?;
            return Err(std::io::Error::from_raw_os_error(1117));
        }
        SystemIo.write_stage(file, bytes)
    }
    fn sync_stage(&self, file: &File) -> std::io::Result<()> {
        if matches!(self.0, Fault::StageSync) {
            return Err(std::io::Error::from_raw_os_error(1117));
        }
        SystemIo.sync_stage(file)
    }
    fn cleanup(&self, file: &File) -> Result<(), MutationError> {
        if matches!(self.0, Fault::Cleanup) {
            return Err(MutationError::RecoveryRequired);
        }
        SystemIo.cleanup(file)
    }
    fn sync_published(&self, file: &File) -> std::io::Result<()> {
        if matches!(self.0, Fault::PublishSync) {
            return Err(std::io::Error::from_raw_os_error(1117));
        }
        SystemIo.sync_published(file)
    }
}

#[test]
fn uncertain_rename_latches_recovery_for_move_and_publication() {
    for publish in [false, true] {
        let f = Fixture::new();
        let mut d = f.domain();
        run(
            &d,
            Operation::Create {
                name: "a",
                bytes: b"before",
            },
        )
        .unwrap();
        d.io = Box::new(FaultIo(Fault::AfterRename));
        let op = if publish {
            Operation::Rewrite {
                name: "a",
                bytes: b"after",
            }
        } else {
            Operation::Rename { from: "a", to: "b" }
        };
        assert_eq!(run(&d, op), Err(MutationError::RecoveryRequired));
        assert_eq!(
            f.bytes(if publish { "a" } else { "b" }),
            if publish {
                b"after".as_slice()
            } else {
                b"before".as_slice()
            }
        );
        assert_eq!(
            run(
                &d,
                Operation::Create {
                    name: "c",
                    bytes: b"next"
                }
            ),
            Err(MutationError::RecoveryRequired)
        );
        assert!(!f.0.join("c").exists());
    }
}

#[test]
fn failures_before_and_after_publication_preserve_distinct_outcomes() {
    for fault in [
        Fault::StageWrite,
        Fault::StageSync,
        Fault::BeforeRename,
        Fault::PublishSync,
    ] {
        let f = Fixture::new();
        let mut d = f.domain();
        run(
            &d,
            Operation::Create {
                name: "a",
                bytes: b"before",
            },
        )
        .unwrap();
        d.io = Box::new(FaultIo(fault));
        let error = run(
            &d,
            Operation::Rewrite {
                name: "a",
                bytes: b"after",
            },
        );
        match fault {
            Fault::StageWrite | Fault::StageSync => {
                assert_eq!(error, Err(MutationError::Denied));
                assert_eq!(f.bytes("a"), b"before");
                assert!(!f.0.join(STAGE).exists());
            }
            Fault::BeforeRename => {
                assert_eq!(error, Err(MutationError::RecoveryRequired));
                assert_eq!(f.bytes("a"), b"before");
                assert_eq!(f.bytes(STAGE), b"after");
            }
            Fault::PublishSync => {
                assert_eq!(error, Err(MutationError::RecoveryRequired));
                assert_eq!(f.bytes("a"), b"after");
                assert!(!f.0.join(STAGE).exists());
            }
            _ => unreachable!(),
        }
        if matches!(fault, Fault::BeforeRename | Fault::PublishSync) {
            assert_eq!(
                run(
                    &d,
                    Operation::Create {
                        name: "b",
                        bytes: b"next"
                    }
                ),
                Err(MutationError::RecoveryRequired)
            );
            assert!(!f.0.join("b").exists());
        }
    }
}

#[test]
fn failed_cleanup_preserves_orphan_and_reopen_refuses_mutation() {
    let f = Fixture::new();
    let mut d = f.domain();
    run(
        &d,
        Operation::Create {
            name: "a",
            bytes: b"before",
        },
    )
    .unwrap();
    d.io = Box::new(FaultIo(Fault::Cleanup));
    let ticket = d.issue().unwrap();
    let cancelled = AtomicBool::new(false);
    assert_eq!(
        d.execute(
            &ticket,
            Operation::Rewrite {
                name: "a",
                bytes: b"after"
            },
            &cancelled,
            || {
                cancelled.store(true, Ordering::Release);
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
    assert_eq!(f.bytes("a"), b"before");
    assert_eq!(f.bytes(STAGE), b"after");
    drop(d);
    let reopened = f.domain();
    assert_eq!(
        run(
            &reopened,
            Operation::Create {
                name: "b",
                bytes: b"next"
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
    assert_eq!(f.bytes(STAGE), b"after");
    assert!(!f.0.join("b").exists());
}

#[test]
fn alternate_ntfs_name_cannot_admit_private_long_name() {
    use windows_sys::Win32::Storage::FileSystem::SetFileShortNameW;
    let f = Fixture::new();
    let private = f.0.join(".private-object");
    fs::write(&private, b"PRIVATE").unwrap();
    let file = OpenOptions::new()
        .access_mode(FILE_GENERIC_WRITE | DELETE)
        .share_mode(SHARING)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&private)
        .unwrap();
    let short: Vec<u16> = "PUBLIC.TXT".encode_utf16().chain(Some(0)).collect();
    assert_ne!(
        unsafe { SetFileShortNameW(file.as_raw_handle(), short.as_ptr()) },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    drop(file);
    assert_eq!(f.bytes("PUBLIC.TXT"), b"PRIVATE");
    assert_eq!(
        identity(&File::open(&private).unwrap()).unwrap(),
        identity(&File::open(f.0.join("PUBLIC.TXT")).unwrap()).unwrap()
    );
    let d = f.domain();
    for op in [
        Operation::Append {
            name: "PUBLIC.TXT",
            bytes: b"x",
        },
        Operation::Rewrite {
            name: "PUBLIC.TXT",
            bytes: b"x",
        },
        Operation::Rename {
            from: "PUBLIC.TXT",
            to: "moved.txt",
        },
    ] {
        assert_eq!(run(&d, op), Err(MutationError::Denied));
        assert_eq!(fs::read(&private).unwrap(), b"PRIVATE");
        assert!(!f.0.join("moved.txt").exists());
    }
}

#[test]
fn readonly_destination_denies_cleanly_without_blocking_domain() {
    let f = Fixture::new();
    let d = f.domain();
    run(
        &d,
        Operation::Create {
            name: "a",
            bytes: b"before",
        },
    )
    .unwrap();
    let path = f.0.join("a");
    let original_permissions = fs::metadata(&path).unwrap().permissions();
    let mut readonly_permissions = original_permissions.clone();
    readonly_permissions.set_readonly(true);
    fs::set_permissions(&path, readonly_permissions).unwrap();
    let result = run(
        &d,
        Operation::Rewrite {
            name: "a",
            bytes: b"after",
        },
    );
    let append = run(
        &d,
        Operation::Append {
            name: "a",
            bytes: b"x",
        },
    );
    // Always restore the test-owned file's attribute for teardown.
    fs::set_permissions(&path, original_permissions).unwrap();
    assert_eq!(result, Err(MutationError::Denied));
    assert_eq!(append, Err(MutationError::Denied));
    assert_eq!(f.bytes("a"), b"before");
    assert!(!f.0.join(STAGE).exists());
    run(
        &d,
        Operation::Create {
            name: "b",
            bytes: b"next",
        },
    )
    .unwrap();
    assert_eq!(f.bytes("b"), b"next");
}
