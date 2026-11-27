//! Real native engine + SQLite process-exit integration. No production grant.
use super::*;
use jdc_authority_store::mutation_journal::Phase;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
const ID: [u8; 32] = [7; 32];

fn provision(path: &Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "PRAGMA application_id=0x4A444331;
         PRAGMA user_version=2;
         CREATE TABLE protected_state (slot INTEGER PRIMARY KEY CHECK(slot=1), domain BLOB NOT NULL CHECK(typeof(domain)='blob' AND length(domain)=32), epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=8), digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32), sequence BLOB NOT NULL CHECK(typeof(sequence)='blob' AND length(sequence)=8), phase INTEGER NOT NULL CHECK(phase IN (0,1,2,3)), operation_epoch BLOB NOT NULL CHECK(typeof(operation_epoch)='blob' AND length(operation_epoch)=8), request_digest BLOB NOT NULL CHECK(typeof(request_digest)='blob' AND length(request_digest)=32));
         INSERT INTO protected_state VALUES(1,zeroblob(32),x'0000000000000001',zeroblob(32),zeroblob(8),0,zeroblob(8),zeroblob(32));"
    ).unwrap();
    conn.execute(
        "UPDATE protected_state SET domain=?1 WHERE slot=1",
        [ID.as_slice()],
    )
    .unwrap();
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "jdc-journal-native-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::create_dir(p.join("objects")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(p.join("objects"), fs::Permissions::from_mode(0o700)).unwrap();
        }
        provision(&p.join("policy.sqlite3"));
        Self(p)
    }
    fn open(&self) -> JournaledDomain {
        JournaledDomain::open_fixture(&self.0.join("objects"), &self.0.join("policy.sqlite3"), ID)
            .unwrap()
    }
    fn bytes(&self, name: &str) -> Vec<u8> {
        fs::read(self.0.join("objects").join(name)).unwrap()
    }
    fn state(&self) -> Snapshot {
        Journal::open_existing(&self.0.join("policy.sqlite3"), ID)
            .unwrap()
            .snapshot()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(d: &JournaledDomain, sequence: u64, op: Operation<'_>) -> Result<(), MutationError> {
    d.execute(1, sequence, op, &AtomicBool::new(false), || {}, || {})
}

#[test]
fn all_native_operations_are_durably_bound_and_replays_do_not_mutate() {
    let f = Fixture::new();
    let d = f.open();
    let create = Operation::Create {
        name: "a",
        bytes: b"one",
    };
    let expected = request_digest(ID, 1, 1, &create).unwrap();
    run(&d, 1, create).unwrap();
    assert_eq!(f.state().request_digest, expected);
    assert_eq!(f.state().phase, Phase::Committed);
    assert_eq!(
        run(
            &d,
            1,
            Operation::Append {
                name: "a",
                bytes: b"replay"
            }
        ),
        Err(MutationError::Denied)
    );
    assert_eq!(f.bytes("a"), b"one");
    run(
        &d,
        2,
        Operation::Append {
            name: "a",
            bytes: &[0, 255],
        },
    )
    .unwrap();
    assert_eq!(f.bytes("a"), b"one\0\xff");
    run(
        &d,
        3,
        Operation::Rewrite {
            name: "a",
            bytes: b"replacement",
        },
    )
    .unwrap();
    run(&d, 4, Operation::Rename { from: "a", to: "b" }).unwrap();
    assert_eq!(f.bytes("b"), b"replacement");
    assert_eq!(
        run(
            &d,
            5,
            Operation::Create {
                name: "b",
                bytes: b"collision"
            }
        ),
        Err(MutationError::Collision)
    );
    assert_eq!(f.state().phase, Phase::Rejected);
    assert_eq!(f.state().sequence, 5);
    drop(d);
    let d = f.open();
    assert_eq!(
        run(&d, 4, Operation::Rename { from: "b", to: "a" }),
        Err(MutationError::Denied)
    );
    run(
        &d,
        6,
        Operation::Append {
            name: "b",
            bytes: b"!",
        },
    )
    .unwrap();
    assert_eq!(f.bytes("b"), b"replacement!");
}

#[test]
fn pending_is_persisted_before_staging_and_cancelled_operation_is_terminal() {
    let f = Fixture::new();
    let d = f.open();
    let cancelled = AtomicBool::new(false);
    let op = Operation::Create {
        name: "a",
        bytes: b"PRIVATE",
    };
    let digest = request_digest(ID, 1, 1, &op).unwrap();
    assert_eq!(
        d.execute(
            1,
            1,
            op,
            &cancelled,
            || {
                assert_eq!(f.state().phase, Phase::Pending);
                assert_eq!(f.state().request_digest, digest);
                assert!(!f.0.join("objects/a").exists());
                cancelled.store(true, Ordering::Release);
            },
            || {}
        ),
        Err(MutationError::Denied)
    );
    assert_eq!(f.state().phase, Phase::Rejected);
    assert!(!f.0.join("objects/a").exists());
    run(
        &d,
        2,
        Operation::Create {
            name: "a",
            bytes: b"NEXT",
        },
    )
    .unwrap();
    assert_eq!(f.bytes("a"), b"NEXT");
}

#[test]
fn actual_native_commit_without_ack_blocks_after_process_restart() {
    const CHILD: &str = "JDC_NATIVE_JOURNAL_CRASH";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let d =
            JournaledDomain::open_fixture(&root.join("objects"), &root.join("policy.sqlite3"), ID)
                .unwrap();
        d.execute(
            1,
            1,
            Operation::Create {
                name: "a",
                bytes: b"APPLIED",
            },
            &AtomicBool::new(false),
            || {},
            || std::process::exit(77),
        )
        .unwrap();
        panic!("must terminate before journal finish");
    }
    let f = Fixture::new();
    let status=std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact","journaled_mutations::tests::actual_native_commit_without_ack_blocks_after_process_restart"])
        .env(CHILD,&f.0).status().unwrap();
    assert_eq!(status.code(), Some(77));
    assert_eq!(f.bytes("a"), b"APPLIED");
    assert!(!f.0.join("objects/.jdc-stage").exists());
    assert_eq!(f.state().phase, Phase::Pending);
    let d = f.open();
    assert_eq!(
        run(
            &d,
            1,
            Operation::Create {
                name: "a",
                bytes: b"RETRY"
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
    assert_eq!(
        run(
            &d,
            2,
            Operation::Create {
                name: "b",
                bytes: b"NEXT"
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
    assert_eq!(f.bytes("a"), b"APPLIED");
    assert!(!f.0.join("objects/b").exists());
}

#[test]
fn request_digest_is_bound_to_domain_epoch_sequence_operation_and_bytes() {
    let op = Operation::Append {
        name: "a",
        bytes: b"abc",
    };
    let a = request_digest(ID, 1, 1, &op).unwrap();
    assert_ne!(a, request_digest([8; 32], 1, 1, &op).unwrap());
    assert_ne!(a, request_digest(ID, 2, 1, &op).unwrap());
    assert_ne!(a, request_digest(ID, 1, 2, &op).unwrap());
    assert_ne!(
        a,
        request_digest(
            ID,
            1,
            1,
            &Operation::Create {
                name: "a",
                bytes: b"abc"
            }
        )
        .unwrap()
    );
    assert_ne!(
        a,
        request_digest(
            ID,
            1,
            1,
            &Operation::Append {
                name: "ab",
                bytes: b"c"
            }
        )
        .unwrap()
    );
    assert_ne!(
        a,
        request_digest(
            ID,
            1,
            1,
            &Operation::Append {
                name: "a",
                bytes: b"ab!"
            }
        )
        .unwrap()
    );
    assert!(request_digest(
        ID,
        1,
        1,
        &Operation::Create {
            name: "CON",
            bytes: b"x"
        }
    )
    .is_err());
}

#[test]
fn failed_terminal_transaction_never_acknowledges_applied_native_work() {
    let f = Fixture::new();
    let d = f.open();
    let blocker = rusqlite::Connection::open(f.0.join("policy.sqlite3")).unwrap();
    assert_eq!(
        d.execute(
            1,
            1,
            Operation::Create {
                name: "a",
                bytes: b"APPLIED"
            },
            &AtomicBool::new(false),
            || {},
            || {
                // Actual competing SQLite transaction, held until execute returns.
                // The production custody contract must prevent unrelated writers;
                // this fixture exercises the database failure boundary.
                blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
    blocker.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.bytes("a"), b"APPLIED");
    assert_eq!(f.state().phase, Phase::Pending);
    assert_eq!(
        run(
            &d,
            2,
            Operation::Create {
                name: "b",
                bytes: b"next"
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
    drop(d);
    let reopened = f.open();
    assert_eq!(
        run(
            &reopened,
            2,
            Operation::Create {
                name: "b",
                bytes: b"next"
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
    assert!(!f.0.join("objects/b").exists());
}

#[test]
fn failed_begin_does_not_start_native_work() {
    let f = Fixture::new();
    let d = f.open();
    let blocker = rusqlite::Connection::open(f.0.join("policy.sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        d.execute(
            1,
            1,
            Operation::Create {
                name: "a",
                bytes: b"NEVER"
            },
            &AtomicBool::new(false),
            || panic!("native preparation must not run"),
            || panic!("native operation must not run")
        ),
        Err(MutationError::RecoveryRequired)
    );
    blocker.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.state().phase, Phase::Initial);
    assert!(!f.0.join("objects/a").exists());
    assert!(!f.0.join("objects/.jdc-stage").exists());
    assert_eq!(
        run(
            &d,
            1,
            Operation::Create {
                name: "a",
                bytes: b"retry"
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires fresh root-admin-provisioned private tmpfs and actual dedicated service identity"]
fn hosted_verified_mount_executes_journaled_native_mutations() {
    use std::os::unix::fs::PermissionsExt;
    let root = PathBuf::from(std::env::var_os("JDC_T011_ADMITTED_MOUNT").expect("hosted mount"));
    crate::verify_service_identity().unwrap();
    let state = root.join(".jdc-state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let db = state.join("policy.sqlite3");
    provision(&db);
    fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
    let narrower = root.join("narrower");
    fs::create_dir(&narrower).unwrap();
    fs::set_permissions(&narrower, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(JournaledDomain::open_verified_linux(&narrower, ID).is_err());
    assert!(JournaledDomain::open_verified_linux(&state, ID).is_err());
    let domain = JournaledDomain::open_verified_linux(&root, ID).unwrap();
    assert!(JournaledDomain::open_verified_linux(&root, ID).is_err());
    run(
        &domain,
        1,
        Operation::Create {
            name: "admission-proof.bin",
            bytes: b"BEGIN",
        },
    )
    .unwrap();
    run(
        &domain,
        2,
        Operation::Append {
            name: "admission-proof.bin",
            bytes: b"-APPEND",
        },
    )
    .unwrap();
    assert_eq!(
        fs::read(root.join("admission-proof.bin")).unwrap(),
        b"BEGIN-APPEND"
    );
    run(
        &domain,
        3,
        Operation::Rewrite {
            name: "admission-proof.bin",
            bytes: b"REWRITE",
        },
    )
    .unwrap();
    run(
        &domain,
        4,
        Operation::Rename {
            from: "admission-proof.bin",
            to: "admission-final.bin",
        },
    )
    .unwrap();
    assert_eq!(
        fs::read(root.join("admission-final.bin")).unwrap(),
        b"REWRITE"
    );
    assert!(!root.join("admission-proof.bin").exists());
    drop(domain);
    let reopened = JournaledDomain::open_verified_linux(&root, ID).unwrap();
    assert_eq!(
        run(
            &reopened,
            4,
            Operation::Append {
                name: "admission-final.bin",
                bytes: b"REPLAY"
            }
        ),
        Err(MutationError::Denied)
    );
    assert_eq!(
        fs::read(root.join("admission-final.bin")).unwrap(),
        b"REWRITE"
    );
    assert_eq!(
        Journal::open_existing(&db, ID)
            .unwrap()
            .snapshot()
            .unwrap()
            .sequence,
        4
    );
    println!("\nT011_LINUX_ADMITTED_JOURNALED_MUTATIONS_PASS_NONRELEASE");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires actual administrator-imported child bind mount in disposable hosted volume"]
fn hosted_verified_mount_rejects_child_bind_mount() {
    let root = PathBuf::from(std::env::var_os("JDC_T011_ADMITTED_MOUNT").expect("hosted mount"));
    crate::verify_service_identity().unwrap();
    // The earlier positive fixture provisioned the actual DB; the shell
    // fixture independently proves the child mount and exact alias bytes.
    assert_eq!(
        fs::read(root.join("admission-final.bin")).unwrap(),
        b"REWRITE"
    );
    assert!(JournaledDomain::open_verified_linux(&root, ID).is_err());
    assert_eq!(
        fs::read(root.join("admission-final.bin")).unwrap(),
        b"REWRITE"
    );
    println!("\nT011_LINUX_ADMITTED_MOUNT_CHILD_DENIED_NONRELEASE");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the same real hosted mount after administrator removes the child bind mount"]
fn hosted_verified_mount_readmits_after_child_removed() {
    let root = PathBuf::from(std::env::var_os("JDC_T011_ADMITTED_MOUNT").expect("hosted mount"));
    let domain = JournaledDomain::open_verified_linux(&root, ID).unwrap();
    run(
        &domain,
        5,
        Operation::Append {
            name: "admission-final.bin",
            bytes: b"-READMITTED",
        },
    )
    .unwrap();
    assert_eq!(
        fs::read(root.join("admission-final.bin")).unwrap(),
        b"REWRITE-READMITTED"
    );
    println!("\nT011_LINUX_ADMITTED_MOUNT_RESTORED_NONRELEASE");
}

#[cfg(windows)]
#[test]
#[ignore = "requires trusted administrator-provisioned NTFS VHD and independent service SID"]
fn hosted_verified_volume_executes_journaled_native_mutations() {
    // Administrator-controlled working directory and input file, not IPC.
    let input = fs::read_to_string("admission-input.txt").unwrap();
    let fields: Vec<_> = input.lines().collect();
    let [drive, guid, service, owner] = fields.as_slice() else {
        panic!("invalid hosted input")
    };
    let root = Path::new(guid);
    let state = root.join(".jdc-state");
    fs::create_dir(&state).unwrap();
    let db = state.join("policy.sqlite3");
    provision(&db);
    assert!(JournaledDomain::open_verified_windows(drive, guid, owner, service, ID).is_err());
    assert!(JournaledDomain::open_verified_windows(
        drive,
        &format!("{guid}.jdc-state"),
        service,
        owner,
        ID
    )
    .is_err());
    let domain = JournaledDomain::open_verified_windows(drive, guid, service, owner, ID).unwrap();
    assert!(JournaledDomain::open_verified_windows(drive, guid, service, owner, ID).is_err());
    run(
        &domain,
        1,
        Operation::Create {
            name: "admission-proof.bin",
            bytes: b"BEGIN",
        },
    )
    .unwrap();
    run(
        &domain,
        2,
        Operation::Append {
            name: "admission-proof.bin",
            bytes: b"-APPEND",
        },
    )
    .unwrap();
    assert_eq!(
        fs::read(root.join("admission-proof.bin")).unwrap(),
        b"BEGIN-APPEND"
    );
    run(
        &domain,
        3,
        Operation::Rewrite {
            name: "admission-proof.bin",
            bytes: b"REWRITE",
        },
    )
    .unwrap();
    run(
        &domain,
        4,
        Operation::Rename {
            from: "admission-proof.bin",
            to: "admission-final.bin",
        },
    )
    .unwrap();
    assert_eq!(
        fs::read(root.join("admission-final.bin")).unwrap(),
        b"REWRITE"
    );
    assert!(!root.join("admission-proof.bin").exists());
    drop(domain);
    let reopened = JournaledDomain::open_verified_windows(drive, guid, service, owner, ID).unwrap();
    assert_eq!(
        run(
            &reopened,
            4,
            Operation::Append {
                name: "admission-final.bin",
                bytes: b"REPLAY"
            }
        ),
        Err(MutationError::Denied)
    );
    assert_eq!(
        fs::read(root.join("admission-final.bin")).unwrap(),
        b"REWRITE"
    );
    assert_eq!(
        Journal::open_existing(&db, ID)
            .unwrap()
            .snapshot()
            .unwrap()
            .sequence,
        4
    );
    println!("\nT011_WINDOWS_ADMITTED_JOURNALED_MUTATIONS_PASS_NONRELEASE");
}

#[cfg(windows)]
#[test]
#[ignore = "requires the same hosted VHD after administrator adds a second mounted path"]
fn hosted_verified_volume_rejects_alternate_mount() {
    let input = fs::read_to_string("admission-input.txt").unwrap();
    let fields: Vec<_> = input.lines().collect();
    let [drive, guid, service, owner] = fields.as_slice() else {
        panic!("invalid hosted input")
    };
    assert_eq!(
        fs::read(Path::new(guid).join("admission-final.bin")).unwrap(),
        b"REWRITE"
    );
    assert!(JournaledDomain::open_verified_windows(drive, guid, service, owner, ID).is_err());
    println!("\nT011_WINDOWS_ADMITTED_VOLUME_ALIAS_DENIED_NONRELEASE");
}

#[cfg(windows)]
#[test]
#[ignore = "requires same hosted VHD after administrator removes alternate mounted path"]
fn hosted_verified_volume_readmits_after_alias_removed() {
    let input = fs::read_to_string("admission-input.txt").unwrap();
    let fields: Vec<_> = input.lines().collect();
    let [drive, guid, service, owner] = fields.as_slice() else {
        panic!("invalid hosted input")
    };
    let domain = JournaledDomain::open_verified_windows(drive, guid, service, owner, ID).unwrap();
    run(
        &domain,
        5,
        Operation::Append {
            name: "admission-final.bin",
            bytes: b"-READMITTED",
        },
    )
    .unwrap();
    assert_eq!(
        fs::read(Path::new(guid).join("admission-final.bin")).unwrap(),
        b"REWRITE-READMITTED"
    );
    println!("\nT011_WINDOWS_ADMITTED_VOLUME_RESTORED_NONRELEASE");
}

#[cfg(windows)]
#[test]
#[ignore = "requires real hosted VHD and issuer-controlled alias transition while service owns the journal"]
fn hosted_verified_volume_active_owner_rejects_alias() {
    use std::io::{self, Write};
    let input = fs::read_to_string("admission-input.txt").unwrap();
    let fields: Vec<_> = input.lines().collect();
    let [drive, guid, service, owner] = fields.as_slice() else {
        panic!("invalid hosted input")
    };
    let root = Path::new(guid);
    let db = root.join(".jdc-state/policy.sqlite3");
    let domain = JournaledDomain::open_verified_windows(drive, guid, service, owner, ID).unwrap();
    let before = Journal::open_existing(&db, ID).unwrap().snapshot().unwrap();
    assert_eq!(before.sequence, 4);
    assert_eq!(before.phase, Phase::Committed);
    println!("\nT011_WINDOWS_ACTIVE_VOLUME_OWNER_READY_NONRELEASE");
    io::stdout().flush().unwrap();
    // The trusted parent drives the real mount transition and owns a bounded
    // process wait. No client input or production authorization is involved.
    let mut signal = String::new();
    io::stdin().read_line(&mut signal).unwrap();
    assert_eq!(signal.trim_end(), "CHECK");
    assert_eq!(
        run(
            &domain,
            5,
            Operation::Append {
                name: "admission-final.bin",
                bytes: b"FORBIDDEN"
            }
        ),
        Err(MutationError::RecoveryRequired)
    );
    assert_eq!(
        fs::read(root.join("admission-final.bin")).unwrap(),
        b"REWRITE"
    );
    assert_eq!(
        Journal::open_existing(&db, ID).unwrap().snapshot().unwrap(),
        before
    );
    assert!(!root.join(".jdc-stage").exists());
    println!("\nT011_WINDOWS_ACTIVE_VOLUME_ALIAS_DENIED_NONRELEASE");
}

#[cfg(target_os = "linux")]
struct LocalIssuedChild(std::process::Child);
#[cfg(target_os = "linux")]
impl Drop for LocalIssuedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// Local end-to-end proof: actual MCP SDK + JDC dispatcher + Linux kernel
// writer authentication + native journaled mutation. Same-UID disposable
// processes are deliberately not evidence of protected issuer enrollment.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the repository npm build and JDC_T011_NODE absolute Node executable"]
fn local_real_jdc_sdk_to_journaled_native_mutations() {
    use std::{
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::net::UnixListener,
        },
        process::Command,
    };

    let f = Fixture::new();
    let domain = f.open();
    let socket = f.0.join("proof.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let home = f.0.join("client-state");
    fs::create_dir(&home).unwrap();
    let node = PathBuf::from(std::env::var_os("JDC_T011_NODE").expect("absolute Node executable"));
    assert!(node.is_absolute());
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/security/support/t011-issued-sdk-native-mutations.mjs")
        .canonicalize()
        .unwrap();
    let mut child = LocalIssuedChild(
        Command::new(node)
            .arg(script)
            .arg(&socket)
            .arg(&home)
            .spawn()
            .unwrap(),
    );
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.0.id() as libc::pid_t, 0u32) };
    assert!(raw >= 0 && raw <= i64::from(i32::MAX));
    let pinned = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    exercise_sdk_mutation_plan(
        &domain,
        &f.0.join("objects"),
        &f.0.join("policy.sqlite3"),
        &listener,
        &pinned,
        crate::peer_policy::KernelPeer {
            pid: child.0.id() as i32,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        },
        false,
    );
    assert!(
        sdk_ready(pinned.as_raw_fd(), libc::POLLIN, 10000),
        "issued SDK did not finish"
    );
    assert!(child.0.wait().unwrap().success());
    assert!(
        !sdk_ready(listener.as_raw_fd(), libc::POLLIN, 0),
        "unexpected retry"
    );
    assert!(!f.0.join("objects/report.txt").exists());
    assert_eq!(f.bytes("final.txt"), b"REWRITE-LOST");
    assert_eq!(f.state().sequence, 5);
    println!("T011_LINUX_LOCAL_SDK_NATIVE_JOURNAL_EXACT_BYTES_PASS_NONRELEASE");
}

// A genuine SDK cancellation closes the request transport while its issued
// process remains alive. Reject the staged operation, persist rejection,
// and leave both the destination and the outside sentinel unchanged.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the repository npm build and JDC_T011_NODE absolute Node executable"]
fn local_real_sdk_cancelled_staged_mutation_never_publishes() {
    use std::{
        os::{
            fd::{FromRawFd, OwnedFd},
            unix::net::UnixListener,
        },
        process::Command,
    };
    let f = Fixture::new();
    let domain = f.open();
    let sentinel = f.0.join("outside-sentinel");
    fs::write(&sentinel, b"OUTSIDE").unwrap();
    let socket = f.0.join("proof.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let completion_listener = UnixListener::bind(f.0.join("proof.sock.completion")).unwrap();
    let home = f.0.join("client-state");
    fs::create_dir(&home).unwrap();
    let node = PathBuf::from(std::env::var_os("JDC_T011_NODE").expect("absolute Node executable"));
    assert!(node.is_absolute());
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/security/support/t011-issued-sdk-native-mutations.mjs")
        .canonicalize()
        .unwrap();
    let mut child = LocalIssuedChild(
        Command::new(node)
            .arg(script)
            .arg(&socket)
            .arg(&home)
            .arg("--cancel-before-commit")
            .spawn()
            .unwrap(),
    );
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.0.id() as libc::pid_t, 0u32) };
    assert!(raw >= 0 && raw <= i64::from(i32::MAX));
    let pinned = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let peer = crate::peer_policy::KernelPeer {
        pid: child.0.id() as i32,
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    };
    assert_eq!(f.state().sequence, 0);
    exercise_sdk_cancellation(
        &domain,
        &f.0.join("objects"),
        &f.0.join("policy.sqlite3"),
        &listener,
        &completion_listener,
        &pinned,
        peer,
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"OUTSIDE");
    assert!(child.0.wait().unwrap().success());
    println!("T011_LINUX_NATIVE_JOURNAL_CANCELLED_STAGED_SDK_MUTATION_PASS_NONRELEASE");
}

#[cfg(target_os = "linux")]
fn exercise_sdk_cancellation(
    domain: &JournaledDomain,
    root: &Path,
    db: &Path,
    listener: &std::os::unix::net::UnixListener,
    completion_listener: &std::os::unix::net::UnixListener,
    pinned: &std::os::fd::OwnedFd,
    peer: crate::peer_policy::KernelPeer,
) {
    use crate::linux_message_origin::{enable_writer_credentials, receive_attested_frame};
    use std::{
        io::{Read, Write},
        os::fd::AsRawFd,
        time::Duration,
    };
    let snapshot = || Journal::open_existing(db, ID).unwrap().snapshot().unwrap();
    let before = snapshot();
    let sequence = before.sequence.checked_add(1).unwrap();
    assert!(!root.join("cancelled.txt").exists());
    assert!(sdk_alive(pinned));
    assert!(sdk_ready(
        completion_listener.as_raw_fd(),
        libc::POLLIN,
        10000
    ));
    let mut completion = completion_listener.accept().unwrap().0;
    assert_eq!(observe_kernel_peer(&completion).unwrap(), peer);
    completion
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    assert!(sdk_ready(listener.as_raw_fd(), libc::POLLIN, 10000));
    let mut conn = listener.accept().unwrap().0;
    assert_eq!(observe_kernel_peer(&conn).unwrap(), peer);
    enable_writer_credentials(&conn).unwrap();
    conn.set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    conn.write_all(b"C").unwrap();
    let received = receive_attested_frame(&conn, peer, 4096, Duration::from_secs(5)).unwrap();
    assert_eq!(
        received,
        sdk_mutation_payload(1, b"/managed/cancelled.txt", b"MUST-NOT-PUBLISH")
    );
    let op = Operation::Create {
        name: "cancelled.txt",
        bytes: b"MUST-NOT-PUBLISH",
    };
    let digest = request_digest(ID, before.epoch, sequence, &op).unwrap();
    let result = execute_sdk_journaled_operation(domain, db, sequence, op, || {
        assert_eq!(snapshot().phase, Phase::Pending);
        assert_eq!(
            fs::read(root.join(".jdc-stage")).unwrap(),
            b"MUST-NOT-PUBLISH"
        );
        assert!(!root.join("cancelled.txt").exists());
        conn.write_all(b"S").unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(
            conn.read(&mut [0u8; 1]).unwrap(),
            0,
            "actual cancellation must close the request socket"
        );
        assert!(
            sdk_alive(pinned),
            "original process must remain live after cancellation"
        );
        linux_sdk_commit_allowed(&conn, pinned)
    });
    assert_eq!(result, Err(MutationError::Denied));
    let after = snapshot();
    assert_eq!(after.phase, Phase::Rejected);
    assert_eq!(after.sequence, sequence);
    assert_eq!(after.request_digest, digest);
    assert_eq!(after.epoch, before.epoch);
    assert!(!root.join("cancelled.txt").exists());
    assert!(!root.join(".jdc-stage").exists());
    completion.write_all(b"V").unwrap();
    drop(completion);
    drop(conn);
    assert!(sdk_ready(pinned.as_raw_fd(), libc::POLLIN, 10000));
    assert!(
        !sdk_ready(listener.as_raw_fd(), libc::POLLIN, 0),
        "no retry after cancellation"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a hosted admitted mount and a root-issued SDK process"]
fn hosted_root_issued_sdk_to_journaled_native_mutations() {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    let root = PathBuf::from(std::env::var_os("JDC_T011_ADMITTED_MOUNT").unwrap());
    let socket = PathBuf::from(std::env::var_os("JDC_T011_MUTATION_SOCKET").unwrap());
    let issuer = PathBuf::from(std::env::var_os("JDC_T011_MUTATION_ISSUER_SOCKET").unwrap());
    crate::verify_service_identity().unwrap();
    let domain = JournaledDomain::open_verified_linux(&root, ID).unwrap();
    let db = root.join(".jdc-state/policy.sqlite3");
    let before = Journal::open_existing(&db, ID).unwrap().snapshot().unwrap();
    assert_eq!(before.sequence, 5);
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o777)).unwrap();
    let issuer_listener = UnixListener::bind(&issuer).unwrap();
    fs::set_permissions(&issuer, fs::Permissions::from_mode(0o600)).unwrap();
    let approved = fixture_issuer::fixture_client().unwrap();
    assert_ne!(approved.uid, unsafe { libc::geteuid() });
    assert_ne!(approved.gid, unsafe { libc::getegid() });
    // Dedicated test-owned event: the runner blocks on this FIFO, without
    // polling service readiness. It is not an authority credential.
    use std::io::Write;
    let ready = PathBuf::from(std::env::var_os("JDC_T011_MUTATION_READY_FIFO").unwrap());
    let mut signal = fs::OpenOptions::new().write(true).open(ready).unwrap();
    signal.write_all(b"JDC_MUTATION_LISTENERS_READY\n").unwrap();
    drop(signal);
    let (pid, pinned) = fixture_issuer::receive_attestation(&issuer_listener).unwrap();
    exercise_sdk_mutation_plan(
        &domain,
        &root,
        &db,
        &listener,
        &pinned,
        crate::peer_policy::KernelPeer {
            pid: pid as i32,
            uid: approved.uid,
            gid: approved.gid,
        },
        true,
    );
    println!("\nT011_LINUX_ROOT_ISSUED_REAL_JDC_JOURNALED_MUTATIONS_PASS_NONRELEASE");
}

// A fresh, independently issued SDK process must exercise cancellation
// on the same admitted journal after the successful mutation sequence.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the hosted admitted mount and a second root-issued SDK process"]
fn hosted_root_issued_sdk_cancelled_staged_mutation_never_publishes() {
    use std::{
        io::Write,
        os::unix::{fs::PermissionsExt, net::UnixListener},
    };
    let root = PathBuf::from(std::env::var_os("JDC_T011_ADMITTED_MOUNT").unwrap());
    let socket = PathBuf::from(std::env::var_os("JDC_T011_MUTATION_SOCKET").unwrap());
    let issuer = PathBuf::from(std::env::var_os("JDC_T011_MUTATION_ISSUER_SOCKET").unwrap());
    crate::verify_service_identity().unwrap();
    let domain = JournaledDomain::open_verified_linux(&root, ID).unwrap();
    let db = root.join(".jdc-state/policy.sqlite3");
    let before = Journal::open_existing(&db, ID).unwrap().snapshot().unwrap();
    assert_eq!(before.sequence, 10);
    assert_eq!(before.phase, Phase::Committed);
    assert_eq!(fs::read(root.join("final.txt")).unwrap(), b"REWRITE-LOST");
    let mut completion_path = socket.as_os_str().to_os_string();
    completion_path.push(".completion");
    let completion_path = PathBuf::from(completion_path);
    let listener = UnixListener::bind(&socket).unwrap();
    let completion = UnixListener::bind(&completion_path).unwrap();
    let issuer_listener = UnixListener::bind(&issuer).unwrap();
    for path in [&socket, &completion_path] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o777)).unwrap();
    }
    fs::set_permissions(&issuer, fs::Permissions::from_mode(0o600)).unwrap();
    let approved = fixture_issuer::fixture_client().unwrap();
    assert_ne!(approved.uid, unsafe { libc::geteuid() });
    assert_ne!(approved.gid, unsafe { libc::getegid() });
    let ready = PathBuf::from(std::env::var_os("JDC_T011_MUTATION_READY_FIFO").unwrap());
    let mut signal = fs::OpenOptions::new().write(true).open(ready).unwrap();
    signal
        .write_all(b"JDC_MUTATION_CANCEL_LISTENERS_READY\n")
        .unwrap();
    drop(signal);
    let (pid, pinned) = fixture_issuer::receive_attestation(&issuer_listener).unwrap();
    exercise_sdk_cancellation(
        &domain,
        &root,
        &db,
        &listener,
        &completion,
        &pinned,
        crate::peer_policy::KernelPeer {
            pid: pid as i32,
            uid: approved.uid,
            gid: approved.gid,
        },
    );
    let after = Journal::open_existing(&db, ID).unwrap().snapshot().unwrap();
    assert_eq!(after.sequence, 11);
    assert_eq!(after.phase, Phase::Rejected);
    assert_eq!(fs::read(root.join("final.txt")).unwrap(), b"REWRITE-LOST");
    println!("T011_LINUX_ADMITTED_JOURNAL_CANCELLED_STAGED_SDK_MUTATION_PASS_NONRELEASE");
}

#[cfg(target_os = "linux")]
use crate::{linux_peer::observe_kernel_peer, peer_policy::DedicatedAccount};
#[cfg(target_os = "linux")]
#[path = "linux_fixture_issuer.rs"]
mod fixture_issuer;

#[cfg(target_os = "linux")]
fn sdk_ready(fd: i32, events: i16, timeout: i32) -> bool {
    let mut p = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, timeout) == 1 && p.revents & events != 0 }
}
#[cfg(target_os = "linux")]
fn sdk_alive(fd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsRawFd;
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, 0) == 0 }
}
#[cfg(target_os = "linux")]
fn linux_sdk_commit_allowed(
    connection: &std::os::unix::net::UnixStream,
    pinned: &std::os::fd::OwnedFd,
) -> bool {
    use std::os::fd::AsRawFd;
    // The issued process can remain alive after aborting its request.
    // At the publication fence, EOF, half-close, error, extra data or
    // unverified socket state must deny the staged mutation. This is one
    // commit-time observation, not a polling loop or a promise to undo a
    // namespace operation that has already entered the kernel.
    let mut status = libc::pollfd {
        fd: connection.as_raw_fd(),
        events: libc::POLLIN | libc::POLLRDHUP,
        revents: 0,
    };
    sdk_alive(pinned) && unsafe { libc::poll(&mut status, 1, 0) } == 0
}

#[cfg(target_os = "linux")]
fn hosted_peer_gate(
    listener: &std::os::unix::net::UnixListener,
    pinned: &std::os::fd::OwnedFd,
    expected: crate::peer_policy::KernelPeer,
) -> std::os::unix::net::UnixStream {
    use std::{
        io::{BufRead, BufReader, Write},
        os::fd::AsRawFd,
        time::{Duration, Instant},
    };
    let start = Instant::now();
    // Open the completion reader while the runner still holds its end,
    // before emitting readiness. Otherwise a fast writer could close
    // the FIFO before we open it and lose the completion event.
    let done = PathBuf::from(std::env::var_os("JDC_T011_MUTATION_PROBES_DONE_FIFO").unwrap());
    let file = fs::File::open(done).unwrap();
    let accept = || {
        let remaining = Duration::from_secs(12)
            .checked_sub(start.elapsed())
            .unwrap();
        assert!(sdk_ready(
            listener.as_raw_fd(),
            libc::POLLIN,
            remaining.as_millis() as i32
        ));
        let conn = listener.accept().unwrap().0;
        assert!(sdk_alive(pinned));
        conn
    };
    // The authentic socket must be retained BEFORE either negative probe.
    let authentic = accept();
    assert_eq!(observe_kernel_peer(&authentic).unwrap(), expected);
    let ready = PathBuf::from(std::env::var_os("JDC_T011_MUTATION_READY_FIFO").unwrap());
    let mut signal = fs::OpenOptions::new().write(true).open(ready).unwrap();
    signal.write_all(b"JDC_MUTATION_AUTHENTIC_HELD\n").unwrap();
    drop(signal);
    let mut same = false;
    let mut foreign = false;
    for _ in 0..2 {
        let mut conn = accept();
        let observed = observe_kernel_peer(&conn).unwrap();
        assert_ne!(observed, expected);
        if observed.uid == expected.uid && observed.gid == expected.gid {
            assert!(!same);
            same = true;
        } else {
            assert_ne!(observed.uid, expected.uid);
            assert!(!foreign);
            foreign = true;
        }
        conn.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        conn.write_all(b"D").unwrap();
        drop(conn);
    }
    assert!(same && foreign);
    // Runner confirms both independent clients consumed D and EOF.
    let remaining = Duration::from_secs(12)
        .checked_sub(start.elapsed())
        .unwrap();
    assert!(sdk_ready(
        file.as_raw_fd(),
        libc::POLLIN,
        remaining.as_millis() as i32
    ));
    let mut line = String::new();
    BufReader::new(file).read_line(&mut line).unwrap();
    assert_eq!(line, "JDC_MUTATION_PROBES_DONE\n");
    assert!(sdk_alive(pinned));
    println!("\nT011_LINUX_MUTATION_LIVE_ISSUED_CLIENT_DISTINCT_PEERS_DENIED_NONRELEASE");
    authentic
}
#[cfg(target_os = "linux")]
fn exercise_sdk_mutation_plan(
    domain: &JournaledDomain,
    root: &Path,
    db: &Path,
    listener: &std::os::unix::net::UnixListener,
    pinned: &std::os::fd::OwnedFd,
    expected_peer: crate::peer_policy::KernelPeer,
    hosted: bool,
) {
    use crate::linux_message_origin::{enable_writer_credentials, receive_attested_frame};
    use std::{io::Write, os::fd::AsRawFd, time::Duration};
    let mut first = if hosted {
        Some(hosted_peer_gate(listener, pinned, expected_peer))
    } else {
        None
    };
    exercise_sdk_mutation_plan_with_commit_gate(
        domain,
        root,
        db,
        |_| {
            let mut conn = first.take().unwrap_or_else(|| {
                assert!(
                    sdk_ready(listener.as_raw_fd(), libc::POLLIN, 10000),
                    "issued SDK request missing"
                );
                listener.accept().unwrap().0
            });
            let peer = observe_kernel_peer(&conn).unwrap();
            assert_eq!(peer, expected_peer);
            assert!(sdk_alive(pinned));
            enable_writer_credentials(&conn).unwrap();
            conn.set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            conn.write_all(b"C").unwrap();
            let observed =
                receive_attested_frame(&conn, peer, 4096, Duration::from_secs(5)).unwrap();
            assert!(sdk_alive(pinned));
            (conn, observed)
        },
        |conn, byte| conn.write_all(&[byte]).unwrap(),
        || sdk_alive(pinned),
        |conn| linux_sdk_commit_allowed(conn, pinned),
    );
}

fn sdk_mutation_payload(tag: u8, first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut data = vec![tag];
    for field in [first, second] {
        data.extend_from_slice(&(field.len() as u32).to_be_bytes());
        data.extend_from_slice(field);
    }
    data
}

fn execute_sdk_journaled_operation(
    domain: &JournaledDomain,
    db: &Path,
    sequence: u64,
    op: Operation<'_>,
    can_commit: impl FnOnce() -> bool,
) -> Result<(), MutationError> {
    let digest = request_digest(ID, 1, sequence, &op).unwrap();
    let cancelled = AtomicBool::new(false);
    domain.execute(
        1,
        sequence,
        op,
        &cancelled,
        || {
            if !can_commit() {
                cancelled.store(true, Ordering::Release);
            }
            let state = Journal::open_existing(db, ID).unwrap().snapshot().unwrap();
            assert_eq!(state.phase, Phase::Pending);
            assert_eq!(state.request_digest, digest);
        },
        || {},
    )
}

fn exercise_sdk_mutation_plan_with_commit_gate<C>(
    domain: &JournaledDomain,
    root: &Path,
    db: &Path,
    mut receive: impl FnMut(usize) -> (C, Vec<u8>),
    mut reply: impl FnMut(&mut C, u8),
    live: impl Fn() -> bool,
    commit_gate: impl Fn(&C) -> bool,
) {
    let payload = sdk_mutation_payload;
    // A trusted fixture plan specifies the complete allowed requests;
    // exact matching means no client-selected root, grant or sequence.
    let plan = [
        (payload(1, b"/managed/ungranted.txt", b"never"), None),
        (
            payload(1, b"/managed/report.txt", b"BEGIN"),
            Some(Operation::Create {
                name: "report.txt",
                bytes: b"BEGIN",
            }),
        ),
        (
            payload(2, b"/managed/report.txt", b"-APPEND"),
            Some(Operation::Append {
                name: "report.txt",
                bytes: b"-APPEND",
            }),
        ),
        (
            payload(1, b"/managed/report.txt", b"REWRITE"),
            Some(Operation::Rewrite {
                name: "report.txt",
                bytes: b"REWRITE",
            }),
        ),
        (
            payload(3, b"/managed/report.txt", b"/managed/final.txt"),
            Some(Operation::Rename {
                from: "report.txt",
                to: "final.txt",
            }),
        ),
        (
            payload(2, b"/managed/final.txt", b"-LOST"),
            Some(Operation::Append {
                name: "final.txt",
                bytes: b"-LOST",
            }),
        ),
    ];
    let initial = Journal::open_existing(db, ID).unwrap().snapshot().unwrap();
    let snapshot = || Journal::open_existing(db, ID).unwrap().snapshot().unwrap();
    for (index, (expected, op)) in plan.into_iter().enumerate() {
        let (mut conn, observed) = receive(index);
        assert!(live());
        assert_eq!(observed, expected, "fixed issued grant/request mismatch");
        if let Some(op) = op {
            let sequence = initial.sequence.checked_add(index as u64).unwrap();
            let digest = request_digest(ID, 1, sequence, &op).unwrap();
            execute_sdk_journaled_operation(domain, db, sequence, op, || commit_gate(&conn))
                .unwrap();
            let state = snapshot();
            assert_eq!(state.phase, Phase::Committed);
            assert_eq!(state.sequence, sequence);
            assert_eq!(state.request_digest, digest);
            match index {
                1 => assert_eq!(fs::read(root.join("report.txt")).unwrap(), b"BEGIN"),
                2 => assert_eq!(fs::read(root.join("report.txt")).unwrap(), b"BEGIN-APPEND"),
                3 => assert_eq!(fs::read(root.join("report.txt")).unwrap(), b"REWRITE"),
                4 => assert_eq!(fs::read(root.join("final.txt")).unwrap(), b"REWRITE"),
                5 => assert_eq!(fs::read(root.join("final.txt")).unwrap(), b"REWRITE-LOST"),
                _ => unreachable!(),
            }
            if index != 5 {
                reply(&mut conn, b'A');
            }
            // Last request deliberately loses the acknowledgment after the
            // actual native commit and terminal SQLite transaction.
        } else {
            assert_eq!(snapshot(), initial);
            assert!(!root.join("ungranted.txt").exists());
            reply(&mut conn, b'D');
        }
        drop(conn);
    }
    assert!(!root.join("report.txt").exists());
    assert_eq!(fs::read(root.join("final.txt")).unwrap(), b"REWRITE-LOST");
    assert_eq!(snapshot().sequence, initial.sequence + 5);
}

#[cfg(windows)]
#[test]
#[ignore = "requires repository npm build and absolute JDC_T011_NODE; same-token local fixture only"]
fn local_windows_real_sdk_issuer_connected_mutation_channel() {
    use crate::windows_mutation_pipe::IssuerConnectedMutationPipe;
    use std::{ffi::OsStr, os::windows::io::AsHandle, time::Duration};
    let f = Fixture::new();
    let domain = f.open();
    let home = f.0.join("client-state");
    fs::create_dir(&home).unwrap();
    let node = PathBuf::from(std::env::var_os("JDC_T011_NODE").expect("absolute Node executable"));
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/security/support/t011-issued-sdk-native-mutations.mjs");
    assert!(node.is_absolute() && node.is_file() && script.is_file());
    let name = format!(
        r"\\.\pipe\JDC-T011-MUTATION-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let log_path = home.join("node-output.log");
    let log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&log_path)
        .unwrap();
    let cmd = format!(
        r#""{}" "{}" --inherited-channel "{}""#,
        node.display(),
        script.display(),
        home.display()
    );
    let system = std::env::var("SystemRoot").unwrap();
    let home_text = home.to_str().unwrap();
    let (pipe, mut child) = IssuerConnectedMutationPipe::issue_local(
        &name,
        &node,
        OsStr::new(&cmd),
        &[
            ("SystemRoot", system.as_str()),
            ("TEMP", home_text),
            ("TMP", home_text),
            ("USERPROFILE", home_text),
        ],
        log.as_handle(),
    )
    .unwrap();
    // The actual creation-time process object is retained with reduced
    // rights. An unrelated live process (even with the same SID) is not it.
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let unrelated =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, std::process::id()) };
    assert!(!unrelated.is_null());
    let unrelated = unsafe { OwnedHandle::from_raw_handle(unrelated) };
    assert!(pipe.matches_issued_process(child.process_handle()));
    assert!(!pipe.matches_issued_process(unrelated.as_handle()));
    assert!(pipe.is_live());
    child.resume().unwrap();
    let diagnostic =
        || fs::read_to_string(&log_path).unwrap_or_else(|_| "<diagnostics unavailable>".into());
    pipe.await_ready().unwrap_or_else(|error| {
        panic!(
            "inherited client readiness failed: {error:?}; {}",
            diagnostic()
        )
    });
    exercise_sdk_mutation_plan_with_commit_gate(
        &domain,
        &f.0.join("objects"),
        &f.0.join("policy.sqlite3"),
        |_| {
            pipe.challenge().unwrap();
            let bytes = pipe
                .receive(4096, Duration::from_secs(5))
                .unwrap_or_else(|error| {
                    panic!("inherited frame failed: {error:?}; {}", diagnostic())
                });
            (&pipe, bytes)
        },
        |pipe, byte| pipe.reply(byte).unwrap(),
        || pipe.is_live(),
        |pipe| pipe.commit_allowed(),
    );
    drop(pipe); // actual peer closure after committed final operation
    child.wait_for_exit(Duration::from_secs(10)).unwrap();
    assert_eq!(
        child.exit_code(),
        Ok(0),
        "{}",
        fs::read_to_string(&log_path).unwrap()
    );
    assert!(fs::read_to_string(&log_path)
        .unwrap()
        .contains("T011_WINDOWS_LOCAL_ISSUER_CONNECTED_SDK_MUTATION_CLIENT_PASS_NONRELEASE"));
    assert_eq!(f.bytes("final.txt"), b"REWRITE-LOST");
    assert_eq!(f.state().sequence, 5);
    println!("T011_WINDOWS_LOCAL_ISSUER_CONNECTED_SDK_MUTATIONS_PASS_NONRELEASE");
}

// Real SDK cancellation on the inherited Windows channel, before native
// publication. Local fixture only: no SCM or admitted-volume verdict.
#[cfg(windows)]
#[test]
#[ignore = "requires repository npm build and absolute JDC_T011_NODE; local cancellation fixture"]
fn local_windows_issued_sdk_cancelled_staged_mutation_never_publishes() {
    use crate::{
        windows_mutation_pipe::{IssuerConnectedMutationPipe, MutationPipe},
        windows_pipe_peer::observe_process_sid,
    };
    use std::{ffi::OsStr, os::windows::io::AsHandle, time::Duration};
    let f = Fixture::new();
    let domain = f.open();
    let root = f.0.join("objects");
    let db = f.0.join("policy.sqlite3");
    let sentinel = f.0.join("outside-sentinel");
    fs::write(&sentinel, b"OUTSIDE").unwrap();
    let home = f.0.join("client-state");
    fs::create_dir(&home).unwrap();
    let node = PathBuf::from(std::env::var_os("JDC_T011_NODE").expect("absolute Node executable"));
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/security/support/t011-issued-sdk-native-mutations.mjs");
    assert!(node.is_absolute() && node.is_file() && script.is_file());
    let name = format!(
        r"\\.\pipe\JDC-T011-MUTATION-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let completion_name = format!("{name}-completion");
    let completion = MutationPipe::create(&completion_name, true).unwrap();
    let log_path = home.join("node-output.log");
    let log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&log_path)
        .unwrap();
    let cmd = format!(
        r#""{}" "{}" --inherited-channel "{}" --cancel-before-commit "{}""#,
        node.display(),
        script.display(),
        home.display(),
        completion_name
    );
    let system = std::env::var("SystemRoot").unwrap();
    let home_text = home.to_str().unwrap();
    let (pipe, mut child) = IssuerConnectedMutationPipe::issue_local(
        &name,
        &node,
        OsStr::new(&cmd),
        &[
            ("SystemRoot", &system),
            ("TEMP", home_text),
            ("TMP", home_text),
            ("USERPROFILE", home_text),
        ],
        log.as_handle(),
    )
    .unwrap();
    assert!(pipe.matches_issued_process(child.process_handle()));
    child.resume().unwrap();
    let diagnostics = || fs::read_to_string(&log_path).unwrap_or_default();
    completion
        .connect(Duration::from_secs(10))
        .unwrap_or_else(|error| {
            panic!(
                "cancellation completion connection failed: {error:?}; {}",
                diagnostics()
            )
        });
    pipe.await_ready().unwrap();
    pipe.challenge().unwrap();
    assert_eq!(
        pipe.receive(4096, Duration::from_secs(5)).unwrap(),
        sdk_mutation_payload(1, b"/managed/cancelled.txt", b"MUST-NOT-PUBLISH")
    );
    let before = f.state();
    assert_eq!(before.sequence, 0);
    let sequence = before.sequence + 1;
    let op = Operation::Create {
        name: "cancelled.txt",
        bytes: b"MUST-NOT-PUBLISH",
    };
    let digest = request_digest(ID, before.epoch, sequence, &op).unwrap();
    let mut cancellation = None;
    let result = execute_sdk_journaled_operation(&domain, &db, sequence, op, || {
        assert_eq!(f.state().phase, Phase::Pending);
        // The Windows stage is held with exclusive sharing; inspect the
        // directory entry, not a second handle to that staged object.
        assert!(fs::read_dir(&root)
            .unwrap()
            .any(|entry| entry.unwrap().file_name() == ".jdc-stage"));
        assert!(!root.join("cancelled.txt").exists());
        cancellation = Some(pipe.observe_staged_cancellation());
        // Fail closed on an unverified outcome. The same commit gate is
        // exercised by the successful inherited-channel mutation plan.
        cancellation == Some(Ok(())) && pipe.commit_allowed()
    });
    assert_eq!(result, Err(MutationError::Denied));
    assert_eq!(
        cancellation,
        Some(Ok(())),
        "actual SDK cancellation required"
    );
    let after = f.state();
    assert_eq!(after.phase, Phase::Rejected);
    assert_eq!(after.sequence, sequence);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.request_digest, digest);
    assert!(!root.join("cancelled.txt").exists());
    assert!(!root.join(".jdc-stage").exists());
    assert_eq!(fs::read(&sentinel).unwrap(), b"OUTSIDE");
    drop(domain);
    let reopened = f.open();
    assert_eq!(f.state(), after);
    assert_eq!(
        run(
            &reopened,
            sequence,
            Operation::Create {
                name: "cancelled.txt",
                bytes: b"MUST-NOT-PUBLISH",
            }
        ),
        Err(MutationError::Denied)
    );
    assert_eq!(f.state(), after);
    assert!(!root.join("cancelled.txt").exists());
    assert!(pipe.is_live());
    completion
        .confirm_cancelled(child.process_handle(), &observe_process_sid().unwrap())
        .unwrap();
    drop(completion);
    drop(pipe);
    child.wait_for_exit(Duration::from_secs(10)).unwrap();
    assert_eq!(child.exit_code(), Ok(0), "{}", diagnostics());
    assert!(diagnostics().contains("T011_WINDOWS_REAL_SDK_CANCELLED_BEFORE_COMMIT_PASS_NONRELEASE"));
    println!("T011_WINDOWS_NATIVE_JOURNAL_CANCELLED_STAGED_SDK_MUTATION_PASS_NONRELEASE");
}

#[cfg(windows)]
#[test]
#[ignore = "requires repository npm build and absolute JDC_T011_NODE; local separate-process fixture"]
fn local_windows_issuer_hands_channel_to_separate_native_service() {
    use crate::windows_mutation_pipe::IssuerConnectedMutationPipe;
    use std::{ffi::OsStr, os::windows::io::AsHandle, time::Duration};
    let f = Fixture::new();
    let home = f.0.join("client-state");
    fs::create_dir(&home).unwrap();
    let node = PathBuf::from(std::env::var_os("JDC_T011_NODE").expect("absolute Node executable"));
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/security/support/t011-issued-sdk-native-mutations.mjs");
    let service_image = std::env::current_exe().unwrap();
    assert!(node.is_absolute() && node.is_file() && script.is_file() && service_image.is_file());
    let name = format!(
        r"\\.\pipe\JDC-T011-MUTATION-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let node_log_path = home.join("node-output.log");
    let service_log_path = f.0.join("service-output.log");
    let node_log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&node_log_path)
        .unwrap();
    let service_log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&service_log_path)
        .unwrap();
    let node_cmd = format!(
        r#""{}" "{}" --inherited-channel "{}""#,
        node.display(),
        script.display(),
        home.display()
    );
    let system = std::env::var("SystemRoot").unwrap();
    let home_text = home.to_str().unwrap();
    let environment = [
        ("SystemRoot", system.as_str()),
        ("TEMP", home_text),
        ("TMP", home_text),
        ("USERPROFILE", home_text),
    ];
    let (pipe, mut client) = IssuerConnectedMutationPipe::issue_local(
        &name,
        &node,
        OsStr::new(&node_cmd),
        &environment,
        node_log.as_handle(),
    )
    .unwrap();
    assert!(pipe.matches_issued_process(client.process_handle()));
    let service_cmd = format!(
        r#""{}" --ignored --exact journaled_mutations::tests::local_inherited_service_mutation_fixture --nocapture"#,
        service_image.display()
    );
    let mut service_environment = environment.to_vec();
    service_environment.push(("JDC_T011_LOCAL_SERVICE_ROOT", f.0.to_str().unwrap()));
    // The native service, not the issuer, owns the SQLite journal and the
    // service end of the SDK stream. No parent copy can mask lost-ack EOF.
    let mut service = pipe
        .launch_local_service(
            &service_image,
            OsStr::new(&service_cmd),
            &service_environment,
            service_log.as_handle(),
        )
        .unwrap();
    assert_ne!(service.pid(), client.pid());
    assert_ne!(service.pid(), std::process::id());
    service.resume().unwrap();
    client.resume().unwrap();
    service
        .wait_for_exit(Duration::from_secs(45))
        .unwrap_or_else(|error| {
            panic!(
                "separate service failed: {error:?}; {}",
                fs::read_to_string(&service_log_path).unwrap_or_default()
            )
        });
    assert_eq!(
        service.exit_code(),
        Ok(0),
        "{}",
        fs::read_to_string(&service_log_path).unwrap_or_default()
    );
    client.wait_for_exit(Duration::from_secs(10)).unwrap();
    assert_eq!(
        client.exit_code(),
        Ok(0),
        "{}",
        fs::read_to_string(&node_log_path).unwrap_or_default()
    );
    assert!(fs::read_to_string(&service_log_path)
        .unwrap()
        .contains("T011_WINDOWS_INHERITED_NATIVE_SERVICE_PASS_NONRELEASE"));
    assert!(fs::read_to_string(&node_log_path)
        .unwrap()
        .contains("T011_WINDOWS_LOCAL_ISSUER_CONNECTED_SDK_MUTATION_CLIENT_PASS_NONRELEASE"));
    assert_eq!(f.bytes("final.txt"), b"REWRITE-LOST");
    assert_eq!(f.state().sequence, 5);
    println!("T011_WINDOWS_SEPARATE_NATIVE_SERVICE_SDK_MUTATIONS_PASS_NONRELEASE");
}

#[cfg(windows)]
#[test]
#[ignore = "subprocess only; requires issuer-inherited native handles"]
fn local_inherited_service_mutation_fixture() {
    use crate::windows_mutation_pipe::IssuerConnectedMutationPipe;
    use std::time::Duration;
    let root =
        PathBuf::from(std::env::var_os("JDC_T011_LOCAL_SERVICE_ROOT").expect("local fixture root"));
    assert!(root.is_absolute());
    let pipe = IssuerConnectedMutationPipe::from_local_service().unwrap();
    let objects = root.join("objects");
    let db = root.join("policy.sqlite3");
    let domain = JournaledDomain::open_fixture(&objects, &db, ID).unwrap();
    pipe.await_ready().unwrap();
    exercise_sdk_mutation_plan_with_commit_gate(
        &domain,
        &objects,
        &db,
        |_| {
            pipe.challenge().unwrap();
            let bytes = pipe.receive(4096, Duration::from_secs(5)).unwrap();
            (&pipe, bytes)
        },
        |pipe, byte| pipe.reply(byte).unwrap(),
        || pipe.is_live(),
        |pipe| pipe.commit_allowed(),
    );
    drop(domain);
    drop(pipe);
    println!("T011_WINDOWS_INHERITED_NATIVE_SERVICE_PASS_NONRELEASE");
}

#[cfg(windows)]
#[test]
#[ignore = "requires repository npm build and absolute JDC_T011_NODE; same-token local fixture only"]
fn local_windows_real_jdc_sdk_to_journaled_native_mutations() {
    use crate::{
        windows_issued_client::IssuedClient, windows_mutation_pipe::MutationPipe,
        windows_pipe_peer::observe_process_sid,
    };
    use std::{ffi::OsStr, os::windows::io::AsRawHandle, time::Duration};
    use windows_sys::Win32::{Foundation::WAIT_TIMEOUT, System::Threading::WaitForSingleObject};
    let f = Fixture::new();
    let domain = f.open();
    let home = f.0.join("client-state");
    fs::create_dir(&home).unwrap();
    let node = PathBuf::from(std::env::var_os("JDC_T011_NODE").expect("absolute Node executable"));
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/security/support/t011-issued-sdk-native-mutations.mjs");
    assert!(node.is_absolute() && node.is_file() && script.is_file());
    let name = format!(
        r"\\.\pipe\JDC-T011-MUTATION-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    // Create the first instance before starting the protected child.
    let mut first = Some(MutationPipe::create(&name, true).unwrap());
    let cmd = format!(
        r#""{}" "{}" "{}" "{}""#,
        node.display(),
        script.display(),
        name,
        home.display()
    );
    let system = std::env::var("SystemRoot").unwrap();
    let home_text = home.to_str().unwrap();
    let mut child = IssuedClient::launch_suspended(
        &node,
        OsStr::new(&cmd),
        &[
            ("SystemRoot", &system),
            ("TEMP", home_text),
            ("TMP", home_text),
            ("USERPROFILE", home_text),
        ],
    )
    .unwrap();
    let sid = observe_process_sid().unwrap();
    child.resume().unwrap();
    let live = || unsafe {
        WaitForSingleObject(child.process_handle().as_raw_handle(), 0) == WAIT_TIMEOUT
    };
    exercise_sdk_mutation_plan_with_commit_gate(
        &domain,
        &f.0.join("objects"),
        &f.0.join("policy.sqlite3"),
        |index| {
            let pipe = first.take().unwrap();
            // Keep an available instance before the current one is closed,
            // so the next legitimate SDK connection cannot race creation.
            // No instance is created after the deliberately lost final ack.

            pipe.connect(Duration::from_secs(10)).unwrap();
            if index < 5 {
                first = Some(MutationPipe::create(&name, false).unwrap());
            }
            pipe.challenge(child.process_handle()).unwrap();
            let bytes = pipe
                .receive(child.process_handle(), &sid, 4096, Duration::from_secs(5))
                .unwrap();
            (pipe, bytes)
        },
        |pipe, byte| pipe.reply(child.process_handle(), &sid, byte).unwrap(),
        live,
        |pipe| pipe.commit_allowed(child.process_handle(), &sid),
    );
    child.wait_for_exit(Duration::from_secs(10)).unwrap();
    assert_eq!(child.exit_code(), Ok(0));
    assert_eq!(f.bytes("final.txt"), b"REWRITE-LOST");
    assert_eq!(f.state().sequence, 5);
    println!("T011_WINDOWS_LOCAL_SDK_NATIVE_JOURNAL_EXACT_BYTES_PASS_NONRELEASE");
}
