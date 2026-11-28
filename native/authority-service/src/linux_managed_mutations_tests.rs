//! Native mutation tests on disposable local files. Not a storage-admission proof.
use super::*;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "jdc-managed-mutation-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn domain(&self) -> Domain {
        Domain::new_fixture(File::open(&self.0).unwrap(), 1).unwrap()
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

fn run(domain: &Domain, operation: Operation<'_>) -> Result<(), MutationError> {
    domain.execute(&domain.issue().unwrap(), operation, &AtomicBool::new(false))
}

#[test]
fn real_create_append_rewrite_rename_and_collision_preserve_bytes() {
    let f = Fixture::new();
    let d = f.domain();
    run(
        &d,
        Operation::Create {
            name: "a",
            bytes: b"one",
        },
    )
    .unwrap();
    let original = fs::metadata(f.0.join("a")).unwrap().ino();
    assert_eq!(
        run(
            &d,
            Operation::Create {
                name: "a",
                bytes: b"other"
            }
        ),
        Err(MutationError::Collision)
    );
    assert_eq!(fs::metadata(f.0.join("a")).unwrap().ino(), original);
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
    run(&d, Operation::Rename { from: "a", to: "b" }).unwrap();
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
fn actual_alias_and_symlink_rejected_without_outside_changes() {
    let f = Fixture::new();
    let outside = Fixture::new();
    fs::write(outside.0.join("sentinel"), b"OUTSIDE").unwrap();
    fs::hard_link(outside.0.join("sentinel"), f.0.join("alias")).unwrap();
    assert_eq!(
        fs::metadata(f.0.join("alias")).unwrap().ino(),
        fs::metadata(outside.0.join("sentinel")).unwrap().ino()
    );
    assert_eq!(fs::metadata(f.0.join("alias")).unwrap().nlink(), 2);
    assert_eq!(f.bytes("alias"), b"OUTSIDE");
    std::os::unix::fs::symlink(outside.0.join("sentinel"), f.0.join("symlink")).unwrap();
    let d = f.domain();
    for name in ["alias", "symlink", "../sentinel", ".jdc-stage"] {
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
fn stale_replay_and_cancelled_operations_do_not_publish() {
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
    let old = d.issue().unwrap();
    d.policy.advance(2).unwrap();
    assert_eq!(
        d.execute(
            &old,
            Operation::Rewrite {
                name: "a",
                bytes: b"after"
            },
            &AtomicBool::new(false)
        ),
        Err(MutationError::Denied)
    );
    let ticket = d.issue().unwrap();
    assert_eq!(
        d.execute(
            &ticket,
            Operation::Append {
                name: "a",
                bytes: b"x"
            },
            &AtomicBool::new(true)
        ),
        Err(MutationError::Denied)
    );
    assert_eq!(
        d.execute(
            &ticket,
            Operation::Append {
                name: "a",
                bytes: b"x"
            },
            &AtomicBool::new(false)
        ),
        Err(MutationError::Denied)
    );
    assert_eq!(f.bytes("a"), b"before");
    assert!(!f.0.join(".jdc-stage").exists());
}

#[test]
fn size_bound_and_orphan_stage_fail_closed() {
    let f = Fixture::new();
    let d = f.domain();
    run(
        &d,
        Operation::Create {
            name: "a",
            bytes: &vec![b'x'; MAX_BYTES],
        },
    )
    .unwrap();
    assert_eq!(
        run(
            &d,
            Operation::Append {
                name: "a",
                bytes: b"x"
            }
        ),
        Err(MutationError::Denied)
    );
    assert_eq!(f.bytes("a").len(), MAX_BYTES);
    fs::write(f.0.join(".jdc-stage"), b"unresolved").unwrap();
    assert_eq!(
        run(
            &d,
            Operation::Rewrite {
                name: "a",
                bytes: b"new"
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
    assert_eq!(f.bytes(".jdc-stage"), b"unresolved");
    assert_eq!(f.bytes("a").len(), MAX_BYTES);
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
            d.execute_with(
                &ticket,
                Operation::Append {
                    name: "a",
                    bytes: b"after"
                },
                &cancelled,
                || {
                    assert_eq!(f.bytes(".jdc-stage"), b"beforeafter");
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
        assert!(!f.0.join(".jdc-stage").exists());
    }
}

#[test]
fn cooperating_instances_and_concurrent_appends_are_serialized() {
    let f = Fixture::new();
    let d = f.domain();
    assert!(Domain::new_fixture(File::open(&f.0).unwrap(), 1).is_err());
    run(
        &d,
        Operation::Create {
            name: "a",
            bytes: b"start",
        },
    )
    .unwrap();
    std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            run(
                &d,
                Operation::Append {
                    name: "a",
                    bytes: b"A",
                },
            )
        });
        let b = scope.spawn(|| {
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
    let contents = f.bytes("a");
    assert!(contents == b"startAB" || contents == b"startBA");
    assert!(!f.0.join(".jdc-stage").exists());
}

#[test]
fn replaced_target_is_not_published_over() {
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
        d.execute_with(
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
    assert!(!f.0.join(".jdc-stage").exists());
}

#[test]
fn hardlink_substitution_during_rewrite_preserves_outside_object() {
    let f = Fixture::new();
    let outside = Fixture::new();
    let sentinel = outside.0.join("sentinel");
    fs::write(&sentinel, b"OUTSIDE").unwrap();
    let original = fs::metadata(&sentinel).unwrap();
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
    let result = d.execute_with(
        &ticket,
        Operation::Rewrite {
            name: "a",
            bytes: b"new",
        },
        &AtomicBool::new(false),
        || {
            fs::rename(f.0.join("a"), f.0.join("original")).unwrap();
            fs::hard_link(&sentinel, f.0.join("a")).unwrap();
            let alias = fs::metadata(f.0.join("a")).unwrap();
            assert_eq!(
                (alias.dev(), alias.ino(), alias.nlink()),
                (original.dev(), original.ino(), 2)
            );
            assert_eq!(f.bytes("a"), b"OUTSIDE");
        },
    );
    assert_eq!(outside.bytes("sentinel"), b"OUTSIDE");
    let observed = fs::metadata(&sentinel).unwrap();
    assert_eq!(
        (observed.dev(), observed.ino(), observed.nlink()),
        (original.dev(), original.ino(), 2)
    );
    let alias = fs::metadata(f.0.join("a")).unwrap();
    assert_eq!((alias.dev(), alias.ino()), (original.dev(), original.ino()));
    assert_eq!(f.bytes("a"), b"OUTSIDE");
    assert_eq!(f.bytes("original"), b"before");
    assert!(!f.0.join(".jdc-stage").exists());
    assert_eq!(result, Err(MutationError::Denied));
}

#[test]
fn foreign_staging_entry_requires_recovery_without_deleting_it() {
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
    // Same-principal interference is outside the approved O threat model.
    // Still fail closed for this observable identity substitution.
    assert_eq!(
        d.execute_with(
            &ticket,
            Operation::Rewrite {
                name: "a",
                bytes: b"new"
            },
            &AtomicBool::new(false),
            || {
                fs::rename(f.0.join(".jdc-stage"), f.0.join("displaced")).unwrap();
                fs::write(f.0.join(".jdc-stage"), b"foreign").unwrap();
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
    assert_eq!(f.bytes("a"), b"before");
    assert_eq!(f.bytes(".jdc-stage"), b"foreign");
    assert_eq!(f.bytes("displaced"), b"new");
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
        let operation = if publish {
            Operation::Rewrite {
                name: "a",
                bytes: b"after",
            }
        } else {
            Operation::Rename { from: "a", to: "b" }
        };
        assert_eq!(run(&d, operation), Err(MutationError::RecoveryRequired));
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

#[derive(Clone, Copy)]
enum Fault {
    AfterRename,
    BeforeRename,
    StageWrite,
    StageSync,
    Cleanup,
    DirectorySync,
}
struct FaultIo(Fault);
impl NativeIo for FaultIo {
    fn rename(&self, root: &File, from: &str, to: &str, replace: bool) -> rustix::io::Result<()> {
        if matches!(self.0, Fault::BeforeRename) {
            return Err(Errno::IO);
        }
        SystemIo.rename(root, from, to, replace)?;
        if matches!(self.0, Fault::AfterRename) {
            return Err(Errno::IO);
        }
        Ok(())
    }
    fn write_stage(&self, file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
        if matches!(self.0, Fault::StageWrite) {
            file.write_all(&bytes[..1])?;
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        SystemIo.write_stage(file, bytes)
    }
    fn sync_stage(&self, file: &File) -> std::io::Result<()> {
        if matches!(self.0, Fault::StageSync) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        SystemIo.sync_stage(file)
    }
    fn cleanup(&self, root: &File) -> rustix::io::Result<()> {
        if matches!(self.0, Fault::Cleanup) {
            return Err(Errno::IO);
        }
        SystemIo.cleanup(root)
    }
    fn sync_root(&self, root: &File) -> std::io::Result<()> {
        if matches!(self.0, Fault::DirectorySync) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        SystemIo.sync_root(root)
    }
}

#[test]
fn failures_before_and_after_publication_preserve_distinct_outcomes() {
    for fault in [
        Fault::StageWrite,
        Fault::StageSync,
        Fault::BeforeRename,
        Fault::DirectorySync,
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
            Fault::DirectorySync => {
                assert_eq!(error, Err(MutationError::RecoveryRequired));
                assert_eq!(f.bytes("a"), b"after");
                assert!(!f.0.join(STAGE).exists());
            }
            _ => unreachable!(),
        }
        if matches!(fault, Fault::BeforeRename | Fault::DirectorySync) {
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
    let cancelled = AtomicBool::new(false);
    let ticket = d.issue().unwrap();
    assert_eq!(
        d.execute_with(
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
fn restrictive_umask_does_not_publish_unreadable_objects() {
    const CHILD: &str = "JDC_MUTATION_UMASK_FIXTURE";
    if std::env::var_os(CHILD).is_some() {
        // Process-local to this exact subprocess test, never the parallel suite.
        unsafe {
            libc::umask(0o400);
        }
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
        assert_eq!(fs::metadata(f.0.join("a")).unwrap().mode() & 0o777, 0o600);
        run(
            &d,
            Operation::Append {
                name: "a",
                bytes: b"after",
            },
        )
        .unwrap();
        assert_eq!(f.bytes("a"), b"beforeafter");
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "linux_managed_mutations::tests::restrictive_umask_does_not_publish_unreadable_objects",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
}
