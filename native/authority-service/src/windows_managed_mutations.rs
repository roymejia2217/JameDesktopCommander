//! Windows test-only native mutation engine. Retained handles and NTFS
//! visibility semantics, not domain admission, durable journal or IPC.
use crate::{
    managed_mutation_contract::{valid_name, MutationError, Operation, MAX_BYTES, STAGE},
    policy_epoch::{PolicyFence, ReadTicket},
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    mem::{offset_of, size_of, MaybeUninit},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FileDispositionInformation, FileRenameInformationEx, NtCreateFile,
            NtSetInformationFile, FILE_CREATE, FILE_DISPOSITION_INFORMATION,
            FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
            FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS,
            FILE_SYNCHRONOUS_IO_NONALERT,
        },
    },
    Win32::{
        Foundation::{
            HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, STATUS_NO_SUCH_FILE,
            STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
            UNICODE_STRING,
        },
        Storage::FileSystem::{
            GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
            DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE, VOLUME_NAME_NONE,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

const LOCK: &str = ".jdc-lock";
const SHARING: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

fn relative_open(
    root: &File,
    name: &str,
    access: u32,
    share: u32,
    disposition: u32,
) -> Result<File, NTSTATUS> {
    // All call sites use an admitted flat public name or a fixed private name.
    if !valid_name(name) && !matches!(name, STAGE | LOCK) {
        return Err(windows_sys::Win32::Foundation::STATUS_INVALID_PARAMETER);
    }
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let length = (wide.len() * size_of::<u16>()) as u16;
    let unicode = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: wide.as_mut_ptr(),
    };
    let attrs = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root.as_raw_handle(),
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle: HANDLE = ptr::null_mut();
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: synchronous operation; all referenced inputs remain live.
    // The returned successful HANDLE has one owner and is never duplicated.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attrs,
            &mut iosb,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status != STATUS_SUCCESS || handle.is_null() {
        return Err(status);
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, MutationError> {
    let mut out = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), out.as_mut_ptr()) } == 0 {
        return Err(MutationError::Denied);
    }
    Ok(unsafe { out.assume_init() })
}

fn identity(file: &File) -> Result<(u32, u64), MutationError> {
    let m = info(file)?;
    Ok((
        m.dwVolumeSerialNumber,
        (u64::from(m.nFileIndexHigh) << 32) | u64::from(m.nFileIndexLow),
    ))
}

fn regular(root: &File, file: &File) -> Result<(), MutationError> {
    let m = info(file)?;
    let size = (u64::from(m.nFileSizeHigh) << 32) | u64::from(m.nFileSizeLow);
    if m.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || m.nNumberOfLinks != 1
        || m.dwVolumeSerialNumber != info(root)?.dwVolumeSerialNumber
        || size > MAX_BYTES as u64
    {
        return Err(MutationError::Denied);
    }
    Ok(())
}

// Query the resolved long leaf on the retained object. The name is
// evidence only; it is never used to reopen or authorize an arbitrary path.
fn require_long_leaf(file: &File, requested: &str) -> Result<(), MutationError> {
    let mut buffer = vec![0u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_NONE,
        )
    } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(MutationError::Denied);
    }
    let leaf = buffer[..length]
        .rsplit(|&unit| unit == u16::from(b'\\'))
        .next()
        .ok_or(MutationError::Denied)?;
    let leaf = String::from_utf16(leaf).map_err(|_| MutationError::Denied)?;
    if !valid_name(&leaf) || !leaf.eq_ignore_ascii_case(requested) {
        return Err(MutationError::Denied);
    }
    Ok(())
}

fn require_replaceable(file: &File) -> Result<(), MutationError> {
    if info(file)?.dwFileAttributes & FILE_ATTRIBUTE_READONLY != 0 {
        return Err(MutationError::Denied);
    }
    Ok(())
}

fn read_target(root: &File, name: &str) -> Result<File, MutationError> {
    if !valid_name(name) {
        return Err(MutationError::Denied);
    }
    let file = relative_open(root, name, FILE_GENERIC_READ | DELETE, SHARING, FILE_OPEN)
        .map_err(|_| MutationError::Denied)?;
    regular(root, &file)?;
    require_long_leaf(&file, name)?;
    Ok(file)
}

fn same_target(root: &File, name: &str, held: &File) -> Result<(), MutationError> {
    regular(root, held)?;
    let observed = read_target(root, name)?;
    if identity(&observed)? != identity(held)? {
        return Err(MutationError::Denied);
    }
    Ok(())
}

// Kernel rename from the retained SOURCE handle to a simple name relative
// to the retained parent. POSIX replacement permits an open old target;
// its identity is checked under the independent single-writer assumption.
fn rename_handle(root: &File, file: &File, to: &str, replace: bool) -> Result<(), NTSTATUS> {
    if !valid_name(to) {
        return Err(windows_sys::Win32::Foundation::STATUS_INVALID_PARAMETER);
    }
    let name: Vec<u16> = to.encode_utf16().collect();
    let byte_len = name.len() * size_of::<u16>();
    let length = size_of::<FILE_RENAME_INFORMATION>() + byte_len;
    // usize alignment is sufficient for the pointer-aligned native structure.
    let mut buffer = vec![0usize; length.div_ceil(size_of::<usize>())];
    let header = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: aligned zeroed storage, bounded UTF-16 tail, synchronous file
    // handle, retained directory and source valid for the entire call.
    let status = unsafe {
        (*header).Anonymous.Flags = if replace {
            FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS
        } else {
            0
        };
        (*header).RootDirectory = root.as_raw_handle();
        (*header).FileNameLength = byte_len as u32;
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            buffer
                .as_mut_ptr()
                .cast::<u8>()
                .add(offset_of!(FILE_RENAME_INFORMATION, FileName))
                .cast::<u16>(),
            name.len(),
        );
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut iosb,
            buffer.as_ptr().cast(),
            length as u32,
            FileRenameInformationEx,
        )
    };
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

fn delete_handle(file: &File) -> Result<(), MutationError> {
    let request = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let mut iosb = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut iosb,
            (&request as *const FILE_DISPOSITION_INFORMATION).cast(),
            size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        )
    };
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(MutationError::RecoveryRequired)
    }
}

// Real kernel operations by default; deterministic test faults at the I/O
// boundary model uncertainty without fabricating namespace outcomes.
trait NativeIo: Send + Sync {
    fn rename(&self, root: &File, source: &File, to: &str, replace: bool) -> Result<(), NTSTATUS> {
        rename_handle(root, source, to, replace)
    }
    fn write_stage(&self, file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
        file.write_all(bytes)
    }
    fn sync_stage(&self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }
    fn cleanup(&self, file: &File) -> Result<(), MutationError> {
        delete_handle(file)
    }
    fn sync_published(&self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }
}
struct SystemIo;
impl NativeIo for SystemIo {}

pub(super) struct Domain {
    root: File,
    io: Box<dyn NativeIo>,
    _lock: File,
    serializer: Mutex<()>,
    policy: PolicyFence,
    recovery: AtomicBool,
}
struct Stage<'a> {
    domain: &'a Domain,
    file: File,
    cleanup: bool,
}
impl Drop for Stage<'_> {
    fn drop(&mut self) {
        // Delete the exact held stage, never a substituted pathname.
        if self.cleanup && self.domain.io.cleanup(&self.file).is_err() {
            self.domain.recovery.store(true, Ordering::Release);
        }
    }
}
enum Prepared<'a> {
    Publish {
        name: &'a str,
        expected: Option<File>,
        stage: Stage<'a>,
    },
    Move {
        from: &'a str,
        to: &'a str,
        expected: File,
    },
}

impl Domain {
    pub(super) fn new_fixture(path: &Path, revision: u64) -> Result<Self, MutationError> {
        // Fixture only; a production root must be independently admitted.
        // Do not share DELETE for this directory handle.
        let root = OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| MutationError::Denied)?;
        Self::new_fixture_with(root, || Ok((revision, ()))).map(|(domain, ())| domain)
    }

    pub(super) fn new_fixture_with<T>(
        root: File,
        open_state: impl FnOnce() -> Result<(u64, T), MutationError>,
    ) -> Result<(Self, T), MutationError> {
        let meta = info(&root)?;
        if meta.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || meta.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(MutationError::Denied);
        }
        // Private exclusive open serializes cooperating broker instances.
        let lock = relative_open(
            &root,
            LOCK,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            FILE_OPEN_IF,
        )
        .map_err(|_| MutationError::Denied)?;
        regular(&root, &lock)?;
        let (revision, state) = open_state()?;
        Ok((
            Self {
                root,
                io: Box::new(SystemIo),
                _lock: lock,
                serializer: Mutex::new(()),
                policy: PolicyFence::new(revision).map_err(|_| MutationError::Denied)?,
                recovery: AtomicBool::new(false),
            },
            state,
        ))
    }
    pub(super) fn issue(&self) -> Result<ReadTicket, MutationError> {
        self.policy.issue_read().map_err(|_| MutationError::Denied)
    }
    fn clear_stage(&self) -> Result<(), MutationError> {
        if self.recovery.load(Ordering::Acquire) {
            return Err(MutationError::RecoveryRequired);
        }
        match relative_open(&self.root, STAGE, FILE_READ_ATTRIBUTES, SHARING, FILE_OPEN) {
            Err(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_NO_SUCH_FILE) => Ok(()),
            _ => Err(MutationError::RecoveryRequired),
        }
    }
    fn stage(&self, bytes: &[u8]) -> Result<Stage<'_>, MutationError> {
        if bytes.len() > MAX_BYTES {
            return Err(MutationError::Denied);
        }
        let file = relative_open(
            &self.root,
            STAGE,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
            0,
            FILE_CREATE,
        )
        .map_err(|e| {
            if e == STATUS_OBJECT_NAME_COLLISION {
                MutationError::RecoveryRequired
            } else {
                MutationError::Denied
            }
        })?;
        let mut stage = Stage {
            domain: self,
            file,
            cleanup: true,
        };
        regular(&self.root, &stage.file)?;
        self.io
            .write_stage(&mut stage.file, bytes)
            .map_err(|_| MutationError::Denied)?;
        self.io
            .sync_stage(&stage.file)
            .map_err(|_| MutationError::Denied)?;
        Ok(stage)
    }
    fn prepare<'a>(&'a self, op: Operation<'a>) -> Result<Prepared<'a>, MutationError> {
        self.clear_stage()?;
        match op {
            Operation::Create { name, bytes } => {
                if !valid_name(name) {
                    return Err(MutationError::Denied);
                }
                Ok(Prepared::Publish {
                    name,
                    expected: None,
                    stage: self.stage(bytes)?,
                })
            }
            Operation::Rewrite { name, bytes } => {
                let expected = read_target(&self.root, name)?;
                require_replaceable(&expected)?;
                Ok(Prepared::Publish {
                    name,
                    expected: Some(expected),
                    stage: self.stage(bytes)?,
                })
            }
            Operation::Append { name, bytes } => {
                if bytes.len() > MAX_BYTES {
                    return Err(MutationError::Denied);
                }
                let mut expected = read_target(&self.root, name)?;
                require_replaceable(&expected)?;
                let mut contents = Vec::new();
                (&mut expected)
                    .take((MAX_BYTES + 1) as u64)
                    .read_to_end(&mut contents)
                    .map_err(|_| MutationError::Denied)?;
                if contents.len() > MAX_BYTES - bytes.len() {
                    return Err(MutationError::Denied);
                }
                contents.extend_from_slice(bytes);
                Ok(Prepared::Publish {
                    name,
                    expected: Some(expected),
                    stage: self.stage(&contents)?,
                })
            }
            Operation::Rename { from, to } => {
                if !valid_name(to) || from.eq_ignore_ascii_case(to) {
                    return Err(MutationError::Denied);
                }
                Ok(Prepared::Move {
                    from,
                    to,
                    expected: read_target(&self.root, from)?,
                })
            }
        }
    }
    fn uncertain(&self) -> MutationError {
        self.recovery.store(true, Ordering::Release);
        MutationError::RecoveryRequired
    }
    fn commit(&self, prepared: Prepared<'_>, cancelled: &AtomicBool) -> Result<(), MutationError> {
        match prepared {
            Prepared::Publish {
                name,
                expected,
                mut stage,
            } => {
                if let Some(ref target) = expected {
                    same_target(&self.root, name, target)?;
                    require_replaceable(target)?;
                }
                regular(&self.root, &stage.file)?;
                if cancelled.load(Ordering::Acquire) {
                    return Err(MutationError::Denied);
                }
                match self
                    .io
                    .rename(&self.root, &stage.file, name, expected.is_some())
                {
                    Ok(()) => stage.cleanup = false,
                    Err(STATUS_OBJECT_NAME_COLLISION) if expected.is_none() => {
                        return Err(MutationError::Collision)
                    }
                    Err(_) => {
                        stage.cleanup = false;
                        return Err(self.uncertain());
                    }
                }
                // Flush published file; namespace crash durability/recovery
                // is a separate gate and is not claimed by this fixture.
                self.io
                    .sync_published(&stage.file)
                    .map_err(|_| self.uncertain())?;
            }
            Prepared::Move { from, to, expected } => {
                same_target(&self.root, from, &expected)?;
                if cancelled.load(Ordering::Acquire) {
                    return Err(MutationError::Denied);
                }
                match self.io.rename(&self.root, &expected, to, false) {
                    Ok(()) => {}
                    Err(STATUS_OBJECT_NAME_COLLISION) => return Err(MutationError::Collision),
                    Err(_) => return Err(self.uncertain()),
                }
            }
        }
        Ok(())
    }
    pub(super) fn execute(
        &self,
        ticket: &ReadTicket,
        op: Operation<'_>,
        cancelled: &AtomicBool,
        before_commit: impl FnOnce(),
    ) -> Result<(), MutationError> {
        let _serial = self
            .serializer
            .lock()
            .map_err(|_| MutationError::RecoveryRequired)?;
        let result = self
            .policy
            .prepare_and_commit_once(
                ticket,
                || {
                    if cancelled.load(Ordering::Acquire) {
                        return Err(MutationError::Denied);
                    }
                    let prepared = self.prepare(op)?;
                    before_commit();
                    Ok(prepared)
                },
                |prepared| self.commit(prepared, cancelled),
            )
            .map_err(|_| MutationError::Denied);
        if self.recovery.load(Ordering::Acquire) {
            return Err(MutationError::RecoveryRequired);
        }
        result?
    }
}

#[path = "windows_managed_mutations_tests.rs"]
mod tests;
