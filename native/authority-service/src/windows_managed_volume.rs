//! Nonshipping whole-volume admission for an administrator-provisioned NTFS
//! VHD fixture. The trusted issuer controls disk attachment, device namespace,
//! token issuance and all privileged accounts. No production authority.
use crate::{managed_mutation_contract::MutationError, windows_pipe_peer::observe_process_sid};
use std::{
    collections::HashSet,
    ffi::c_void,
    fs::{File, OpenOptions},
    mem::{offset_of, size_of, MaybeUninit},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT},
        GetAce, GetLengthSid, GetSecurityDescriptorControl, IsValidAcl, IsValidSid,
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        SE_DACL_PROTECTED,
    },
    Storage::FileSystem::{
        FileIdInfo, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetFileInformationByHandle,
        GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
        GetVolumePathNamesForVolumeNameW, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_SHARE_READ,
        FILE_SHARE_WRITE, VOLUME_NAME_GUID,
    },
};
const FULL: u32 = 0x1f01ff;
const MODIFY: u32 = 0x1301bf;

// This entire module is cfg(test). Report fixed check identifiers and numeric
// kernel errors only, never paths, tokens, SIDs, or ACL contents. Every failed
// check retains the existing deny verdict (including expected negatives).
fn admission_denied(check: &'static str, code: Option<u32>) -> MutationError {
    eprintln!("T011_WINDOWS_VOLUME_ADMISSION_DENIED check={check} os_code={code:?}");
    MutationError::Denied
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
pub(super) fn valid_guid_root(s: &str) -> bool {
    let Some(id) = s
        .strip_prefix(r"\\?\Volume{")
        .and_then(|x| x.strip_suffix("}\\"))
    else {
        return false;
    };
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
pub(super) fn valid_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}
fn open_directory(path: &Path) -> Result<File, MutationError> {
    OpenOptions::new()
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| admission_denied("directory-open", e.raw_os_error().map(|n| n as u32)))
}
fn final_guid_path(file: &File) -> Result<String, MutationError> {
    let mut b = vec![0u16; 32768];
    let n = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            b.as_mut_ptr(),
            b.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
        )
    } as usize;
    if n == 0 {
        return Err(admission_denied(
            "final-guid-api",
            Some(unsafe { GetLastError() }),
        ));
    }
    if n >= b.len() {
        return Err(admission_denied("final-guid-length", None));
    }
    String::from_utf16(&b[..n]).map_err(|_| admission_denied("final-guid-encoding", None))
}
fn info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, MutationError> {
    let mut m = MaybeUninit::uninit();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), m.as_mut_ptr()) } == 0 {
        return Err(admission_denied(
            "file-information",
            Some(unsafe { GetLastError() }),
        ));
    }
    Ok(unsafe { m.assume_init() })
}
#[derive(Debug, Eq, PartialEq)]
struct VolumeIdentity {
    guid: String,
    serial: u64,
    id: [u8; 16],
}
fn volume_identity(file: &File) -> Result<VolumeIdentity, MutationError> {
    let guid = final_guid_path(file)?;
    let m = info(file)?;
    if !valid_guid_root(&guid) {
        return Err(admission_denied("observed-guid-root-syntax", None));
    }
    if m.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || m.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(admission_denied("volume-root-attributes", None));
    }
    let mut fs = [0u16; 32];
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    } == 0
    {
        return Err(admission_denied(
            "volume-information-api",
            Some(unsafe { GetLastError() }),
        ));
    }
    if fs[..5] != [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0] {
        return Err(admission_denied("volume-filesystem", None));
    }
    let mut id = MaybeUninit::<FILE_ID_INFO>::uninit();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            id.as_mut_ptr().cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(admission_denied(
            "volume-file-id",
            Some(unsafe { GetLastError() }),
        ));
    }
    let id = unsafe { id.assume_init() };
    Ok(VolumeIdentity {
        guid,
        serial: id.VolumeSerialNumber,
        id: id.FileId.Identifier,
    })
}
// Mount manager DOS paths are accepted only in the documented absolute
// drive-letter form. An unfamiliar path is not proof of an empty topology.
fn valid_mount_path(path: &str) -> bool {
    let Some(root) = path.get(..3) else {
        return false;
    };
    if !valid_drive(root) || !path.ends_with('\\') {
        return false;
    }
    let tail = &path[3..];
    tail.is_empty()
        || tail[..tail.len() - 1].split('\\').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with(['.', ' '])
                && !part.contains(['/', ':', '\0'])
        })
}

fn parse_mount_paths(units: &[u16]) -> Result<Vec<String>, MutationError> {
    if units == [0] || units == [0, 0] {
        return Ok(Vec::new());
    }
    if !units.ends_with(&[0, 0]) {
        return Err(admission_denied("mount-paths-termination", None));
    }
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for item in units[..units.len() - 2].split(|&u| u == 0) {
        let path =
            String::from_utf16(item).map_err(|_| admission_denied("mount-paths-encoding", None))?;
        if !valid_mount_path(&path) || !seen.insert(path.to_ascii_uppercase()) {
            return Err(admission_denied("mount-paths-invalid-record", None));
        }
        paths.push(path);
    }
    Ok(paths)
}

fn volume_paths(guid: &str) -> Result<Vec<String>, MutationError> {
    let w = wide(guid);
    let mut paths = vec![u16::MAX; 32768];
    let mut count = 0;
    if unsafe {
        GetVolumePathNamesForVolumeNameW(
            w.as_ptr(),
            paths.as_mut_ptr(),
            paths.len() as u32,
            &mut count,
        )
    } == 0
    {
        return Err(admission_denied(
            "mount-paths-api",
            Some(unsafe { GetLastError() }),
        ));
    }
    let count = count as usize;
    if count == 0 || count > paths.len() {
        return Err(admission_denied("mount-paths-length", None));
    }
    parse_mount_paths(&paths[..count])
}

struct VolumeSearch(windows_sys::Win32::Foundation::HANDLE);
impl Drop for VolumeSearch {
    fn drop(&mut self) {
        unsafe { FindVolumeClose(self.0) };
    }
}

// The documented enumeration of all local volumes and their mounted DOS
// paths needs no raw disk handle. Bound both enumeration and individual
// buffers. A failed query, truncation or duplicate GUID denies admission.
fn enumerate_volume_paths() -> Result<Vec<(String, Vec<String>)>, MutationError> {
    let mut name = [u16::MAX; 1024];
    let handle = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(admission_denied(
            "volume-enumeration-start",
            Some(unsafe { GetLastError() }),
        ));
    }
    let search = VolumeSearch(handle);
    let mut inventory = Vec::new();
    let mut seen = HashSet::new();
    for _ in 0..256 {
        let end = name
            .iter()
            .position(|&u| u == 0)
            .ok_or_else(|| admission_denied("volume-enumeration-name", None))?;
        let guid = String::from_utf16(&name[..end])
            .map_err(|_| admission_denied("volume-enumeration-encoding", None))?;
        if !valid_guid_root(&guid) || !seen.insert(guid.to_ascii_uppercase()) {
            return Err(admission_denied("volume-enumeration-identity", None));
        }
        let paths = volume_paths(&guid)?;
        inventory.push((guid, paths));
        name.fill(u16::MAX);
        if unsafe { FindNextVolumeW(search.0, name.as_mut_ptr(), name.len() as u32) } == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_FILES {
                return Ok(inventory);
            }
            return Err(admission_denied("volume-enumeration-next", Some(code)));
        }
    }
    Err(admission_denied("volume-enumeration-bound", None))
}

// In the fixture's issuer-controlled DOS namespace, an exclusively mounted
// volume has one root drive path. A mounted folder inside it is visible in
// another volume's path inventory under that root. This is a point-in-time
// observation, not an atomic mount-manager transaction or a shipping grant.
fn verify_mount_inventory(
    guid: &str,
    drive: &str,
    inventory: &[(String, Vec<String>)],
) -> Result<(), MutationError> {
    if !valid_guid_root(guid) || !valid_drive(drive) {
        return Err(admission_denied("mount-inventory-input", None));
    }
    let mut seen = HashSet::new();
    let mut found = false;
    for (volume, paths) in inventory {
        if !valid_guid_root(volume) || !seen.insert(volume.to_ascii_uppercase()) {
            return Err(admission_denied("mount-inventory-identity", None));
        }
        if paths.iter().any(|path| !valid_mount_path(path)) {
            return Err(admission_denied("mount-inventory-path", None));
        }
        if volume.eq_ignore_ascii_case(guid) {
            if paths.len() != 1 || !paths[0].eq_ignore_ascii_case(drive) {
                return Err(admission_denied("mount-paths-not-exclusive", None));
            }
            found = true;
        } else if paths.iter().any(|p| {
            p.get(..3)
                .is_some_and(|root| root.eq_ignore_ascii_case(drive))
        }) {
            return Err(admission_denied("nested-mount-present", None));
        }
    }
    if !found {
        return Err(admission_denied("mount-inventory-root-missing", None));
    }
    Ok(())
}

fn check_mounts(guid: &str, drive: &str) -> Result<(), MutationError> {
    verify_mount_inventory(guid, drive, &enumerate_volume_paths()?)
}

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}
fn copy_sid(sid: *mut c_void) -> Result<Vec<u8>, MutationError> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(admission_denied("sid-structure", None));
    }
    let len = unsafe { GetLengthSid(sid) } as usize;
    if !(8..=68).contains(&len) {
        return Err(admission_denied("sid-length", None));
    }
    Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), len) }.to_vec())
}
pub(super) fn sid_bytes(s: &str) -> Result<Vec<u8>, MutationError> {
    let mut sid = ptr::null_mut();
    if s.len() > 192 {
        return Err(admission_denied("sid-input-length", None));
    }
    if unsafe { ConvertStringSidToSidW(wide(s).as_ptr(), &mut sid) } == 0 {
        return Err(admission_denied(
            "sid-conversion",
            Some(unsafe { GetLastError() }),
        ));
    }
    let _owned = Local(sid);
    copy_sid(sid)
}
#[derive(Clone)]
struct Ace {
    sid: Vec<u8>,
    mask: u32,
    flags: u8,
}
fn check_aces(aces: &[Ace], service: &[u8], flags: u8) -> Result<(), MutationError> {
    let admin = sid_bytes("S-1-5-32-544")?;
    let system = sid_bytes("S-1-5-18")?;
    if service == admin || service == system || aces.len() != 3 {
        return Err(admission_denied("acl-principal-count", None));
    }
    for (sid, mask) in [
        (admin.as_slice(), FULL),
        (system.as_slice(), FULL),
        (service, MODIFY),
    ] {
        if aces
            .iter()
            .filter(|a| a.sid == sid && a.mask == mask && a.flags == flags)
            .count()
            != 1
        {
            return Err(admission_denied("acl-exact-ace-contract", None));
        }
    }
    Ok(())
}
fn check_root_aces(aces: &[Ace], service: &[u8]) -> Result<(), MutationError> {
    check_aces(aces, service, 3)
}
fn security(
    file: &File,
    service: &[u8],
    issuer_owner: &[u8],
    root: bool,
    directory: bool,
) -> Result<(), MutationError> {
    let mut owner = ptr::null_mut();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut sd = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    let _descriptor = Local(sd);
    if status != 0 {
        return Err(admission_denied("security-info-api", Some(status)));
    }
    if sd.is_null() || acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
        return Err(admission_denied("security-descriptor-structure", None));
    }
    let owner = copy_sid(owner)?;
    if owner != issuer_owner && (root || owner != service) {
        return Err(admission_denied("object-owner", None));
    }
    let (mut control, mut rev) = (0u16, 0u32);
    if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut rev) } == 0 {
        return Err(admission_denied(
            "descriptor-control-api",
            Some(unsafe { GetLastError() }),
        ));
    }
    if (root && control & SE_DACL_PROTECTED == 0) || (!root && control & SE_DACL_PROTECTED != 0) {
        return Err(admission_denied("acl-inheritance-protection", None));
    }
    if unsafe { (*acl).AceCount } != 3 {
        return Err(admission_denied("acl-ace-count", None));
    }
    let mut aces = Vec::new();
    for i in 0..3 {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(acl, i, &mut raw) } == 0 {
            return Err(admission_denied(
                "acl-get-ace-api",
                Some(unsafe { GetLastError() }),
            ));
        }
        if raw.is_null() {
            return Err(admission_denied("acl-null-ace", None));
        }
        // IsValidAcl and GetAce validate the OS-returned ACL; check the
        // fixed header and contained SID length before using SID APIs.
        let a = raw.cast::<ACCESS_ALLOWED_ACE>();
        let header = unsafe { (*a).Header };
        let offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let n = header.AceSize as usize;
        if header.AceType != 0 || n < offset + 8 {
            return Err(admission_denied("acl-ace-header", None));
        }
        let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>().add(offset), n - offset) };
        let len = crate::token_policy::bounded_sid_bytes(bytes)
            .ok_or_else(|| admission_denied("acl-ace-sid-bounds", None))?;
        if len != bytes.len() {
            return Err(admission_denied("acl-ace-sid-length", None));
        }
        let sid = copy_sid(unsafe { raw.cast::<u8>().add(offset).cast() })?;
        aces.push(Ace {
            sid,
            mask: unsafe { (*a).Mask },
            flags: header.AceFlags,
        });
    }
    if root {
        check_root_aces(&aces, service)
    } else {
        check_aces(&aces, service, if directory { 19 } else { 16 })
    }
}

pub(super) struct VerifiedVolume {
    root: File,
    identity: VolumeIdentity,
    drive: String,
    service: Vec<u8>,
    owner: Vec<u8>,
}
impl VerifiedVolume {
    // Issuer-provided values in an explicitly nonshipping hosted fixture;
    // not a client input or a substitute for authenticated SCM issuance.
    pub(super) fn open(
        drive: &str,
        guid: &str,
        service: &str,
        owner: &str,
    ) -> Result<Self, MutationError> {
        if !valid_drive(drive) || !valid_guid_root(guid) {
            return Err(admission_denied("issuer-volume-input", None));
        }
        let service = sid_bytes(service)?;
        let owner = sid_bytes(owner)?;
        if service == owner
            || observe_process_sid().map_err(|_| admission_denied("process-sid-query", None))?
                != service
        {
            return Err(admission_denied("process-principal", None));
        }
        let root = open_directory(Path::new(guid))?;
        let identity = volume_identity(&root)?;
        if !identity.guid.eq_ignore_ascii_case(guid) {
            return Err(admission_denied("issuer-volume-identity", None));
        }
        let result = Self {
            root,
            identity,
            drive: drive.to_ascii_uppercase(),
            service,
            owner,
        };
        result.revalidate()?;
        Ok(result)
    }
    pub(super) fn revalidate(&self) -> Result<(), MutationError> {
        if observe_process_sid().map_err(|_| admission_denied("process-sid-query", None))?
            != self.service
        {
            return Err(admission_denied("process-principal-revalidation", None));
        }
        if volume_identity(&self.root)? != self.identity {
            return Err(admission_denied("held-root-identity", None));
        }
        if volume_identity(&open_directory(Path::new(&self.drive))?)? != self.identity {
            return Err(admission_denied("drive-root-identity", None));
        }
        check_mounts(&self.identity.guid, &self.drive)?;
        security(&self.root, &self.service, &self.owner, true, true)
    }
    pub(super) fn root_handle(&self) -> Result<File, MutationError> {
        self.revalidate()?;
        self.root.try_clone().map_err(|e| {
            admission_denied("root-handle-duplicate", e.raw_os_error().map(|n| n as u32))
        })
    }
    pub(super) fn journal_path(&self) -> Result<PathBuf, MutationError> {
        self.revalidate()?;
        // The fixed state directory and file are inspected on handles, then
        // SQLite opens a path under the trusted exclusive service principal.
        // No client paths and no independent reconciliation writer.
        let dir = Path::new(&self.identity.guid).join(".jdc-state");
        let held = open_directory(&dir)?;
        self.check_child(&held, ".jdc-state", true)?;
        security(&held, &self.service, &self.owner, false, true)?;
        let db = dir.join("policy.sqlite3");
        for (name, required) in [("policy.sqlite3", true), ("policy.sqlite3-journal", false)] {
            let file = match OpenOptions::new()
                .access_mode(FILE_GENERIC_READ)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(dir.join(name))
            {
                Ok(f) => f,
                Err(e) if !required && e.raw_os_error() == Some(2) => continue,
                Err(e) => {
                    return Err(admission_denied(
                        "journal-file-open",
                        e.raw_os_error().map(|n| n as u32),
                    ))
                }
            };
            self.check_child(&file, &format!(".jdc-state\\{name}"), false)?;
            security(&file, &self.service, &self.owner, false, false)?;
        }
        Ok(db)
    }
    fn check_child(
        &self,
        file: &File,
        relative: &str,
        directory: bool,
    ) -> Result<(), MutationError> {
        let m = info(file)?;
        if (m.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
            || m.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (!directory && m.nNumberOfLinks != 1)
        {
            return Err(admission_denied("journal-child-attributes", None));
        }
        if m.dwVolumeSerialNumber != info(&self.root)?.dwVolumeSerialNumber {
            return Err(admission_denied("journal-child-volume", None));
        }
        if !final_guid_path(file)?
            .eq_ignore_ascii_case(&format!("{}{relative}", self.identity.guid))
        {
            return Err(admission_denied("journal-child-path", None));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "windows_managed_volume_tests.rs"]
mod tests;
