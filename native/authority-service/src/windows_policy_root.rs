//! Windows state-directory DACL observation through an already opened OS handle.
//! NON-RELEASE: no pathname bootstrap, authenticated client, policy loader or grant.
use crate::{verify_service_identity, IdentityDenied};
use std::{
    ffi::c_void,
    fs::File,
    mem,
    os::windows::{fs::MetadataExt, io::AsRawHandle},
    ptr,
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FileFsDeviceInformation, NtCreateFile, NtQueryVolumeInformationFile,
            FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        },
        System::SystemServices::{
            FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE, FILE_REMOTE_DEVICE_VSMB,
            FILE_REMOVABLE_MEDIA,
        },
    },
    Win32::{
        Foundation::{LocalFree, OBJ_CASE_INSENSITIVE, UNICODE_STRING},
        Security::{
            AclSizeInformation,
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            EqualSid, GetAclInformation, GetSecurityDescriptorControl, IsValidAcl, IsWellKnownSid,
            WinBuiltinAdministratorsSid, WinLocalSystemSid, ACL, ACL_SIZE_INFORMATION,
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        },
        Storage::FileSystem::{
            FileAttributeTagInfo, FileIdInfo, GetFileInformationByHandleEx,
            GetVolumeInformationByHandleW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_TAG_INFO, FILE_DEVICE_DISK, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
        System::{Ioctl::FILE_DEVICE_DISK_FILE_SYSTEM, IO::IO_STATUS_BLOCK},
    },
};

const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const REQUIRED_ACE_FLAGS: u8 = 0x03; // OI + CI: children and SQLite files must inherit.
const REQUIRED_ADMIN_RIGHTS: u32 = 0x001f_01ff; // Win32 FILE_ALL_ACCESS.
const REQUIRED_SERVICE_RIGHTS: u32 = 0x0003_01bf; // Documented NTFS Modify baseline.
const REQUIRED_PARENT_READ_RIGHTS: u32 = 0x0002_00a9; // ReadAndExecute: no mutation.
const ALLOWED_PARENT_READ_RIGHTS: u32 = REQUIRED_PARENT_READ_RIGHTS | 0x0010_0000;
// Only optional SYNCHRONIZE may be added to the parent's read/traverse ACE.

/// An observation of an existing opened directory; this does not grant access.
/// Neither this value nor a matching DACL authenticates the source of a policy DB.
pub struct ObservedWindowsStateDirectory {
    file: File,
}

impl ObservedWindowsStateDirectory {
    /// Keep using the same kernel object; there is no reopening by pathname.
    pub fn metadata(&self) -> Result<std::fs::Metadata, IdentityDenied> {
        self.file.metadata().map_err(|_| IdentityDenied)
    }

    /// Consume the already DACL-checked kernel directory handle.
    /// Test-only until a reviewed production issuer binds this exact root identity.
    #[cfg(test)]
    pub(crate) fn into_verified_file(self) -> File {
        self.file
    }
}

/// A non-authorizing observation whose parent and root are both pinned OS
/// handles. No file-operation API or grant escapes this value.
///
/// A revoked observation cannot become valid again, even if a privileged
/// namespace actor later restores the original mountpoint. Revalidation
/// is point-in-time only; it does not provide atomic authorization + I/O.
pub(crate) struct ObservedWindowsIsolatedRoot {
    parent: File,
    root: ObservedWindowsStateDirectory,
    child_name: String,
    active: bool,
}

impl ObservedWindowsIsolatedRoot {
    fn revalidate_or_revoke(
        &mut self,
        check: impl FnOnce(&Self) -> Result<(), IdentityDenied>,
    ) -> Result<(), IdentityDenied> {
        if !self.active {
            return Err(IdentityDenied);
        }
        // Fail closed *before* entering any OS or callback check. A caught
        // panic/unwind cannot leave a previously valid observation active.
        // Only a complete successful revalidation may restore active=true.
        self.active = false;
        check(self)?;
        self.active = true;
        Ok(())
    }

    /// Require the real SCM token, protected root/parent ACL, separate
    /// kernel volume and exact relative child identity on every invocation.
    /// This does not issue execution rights or provide an I/O entrypoint.
    pub(crate) fn revalidate(&mut self) -> Result<(), IdentityDenied> {
        self.revalidate_or_revoke(|candidate| {
            verify_service_identity()?;
            let sid = crate::windows_token::service_sid_bytes().map_err(|_| IdentityDenied)?;
            inspect_acl(
                &candidate.root.file,
                &sid,
                ServiceDaclPolicy::MutableProtectedState,
            )?;
            inspect_acl(
                &candidate.parent,
                &sid,
                ServiceDaclPolicy::ReadonlyAdministratorParent,
            )?;
            verify_preopened_volume_separation(&candidate.parent, &candidate.root.file)?;
            verify_preopened_named_child_identity(
                &candidate.parent,
                &candidate.root.file,
                &candidate.child_name,
            )
        })
    }

    // Kernel-only local regression. This constructor/test hook is compiled
    // out of the real service and cannot attest SCM identity or grant I/O.
    #[cfg(test)]
    fn from_preopened_kernel_fixture(
        parent: &File,
        root: File,
        child: &str,
    ) -> Result<Self, IdentityDenied> {
        verify_preopened_named_child_identity(parent, &root, child)?;
        Ok(Self {
            parent: parent.try_clone().map_err(|_| IdentityDenied)?,
            root: ObservedWindowsStateDirectory { file: root },
            child_name: child.to_owned(),
            active: true,
        })
    }

    #[cfg(test)]
    fn revalidate_kernel_binding_only_for_test(&mut self) -> Result<(), IdentityDenied> {
        self.revalidate_or_revoke(|candidate| {
            verify_preopened_named_child_identity(
                &candidate.parent,
                &candidate.root.file,
                &candidate.child_name,
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Principal {
    LocalSystem,
    Administrators,
    Service,
    Foreign,
}

#[derive(Clone, Copy)]
struct AceSummary {
    principal: Principal,
    mask: u32,
    flags: u8,
}

#[derive(Clone, Copy)]
enum ServiceDaclPolicy {
    MutableProtectedState,
    ReadonlyAdministratorParent,
}

fn validate_ace_set(aces: &[AceSummary]) -> Result<(), IdentityDenied> {
    validate_ace_set_with(aces, ServiceDaclPolicy::MutableProtectedState)
}

fn validate_parent_ace_set(aces: &[AceSummary]) -> Result<(), IdentityDenied> {
    validate_ace_set_with(aces, ServiceDaclPolicy::ReadonlyAdministratorParent)
}

fn service_ace_matches(mask: u32, policy: ServiceDaclPolicy) -> bool {
    match policy {
        ServiceDaclPolicy::MutableProtectedState => {
            mask & REQUIRED_SERVICE_RIGHTS == REQUIRED_SERVICE_RIGHTS
                && mask & (WRITE_DAC | WRITE_OWNER | GENERIC_ALL) == 0
        }
        ServiceDaclPolicy::ReadonlyAdministratorParent => {
            mask & REQUIRED_PARENT_READ_RIGHTS == REQUIRED_PARENT_READ_RIGHTS
                && mask & !ALLOWED_PARENT_READ_RIGHTS == 0
        }
    }
}

fn validate_ace_set_with(
    aces: &[AceSummary],
    policy: ServiceDaclPolicy,
) -> Result<(), IdentityDenied> {
    if aces.len() != 3 {
        return Err(IdentityDenied);
    }
    let (mut system, mut admins, mut service) = (false, false, false);
    for ace in aces {
        if ace.flags != REQUIRED_ACE_FLAGS || ace.mask == 0 {
            return Err(IdentityDenied);
        }
        match ace.principal {
            Principal::LocalSystem
                if !system && ace.mask & REQUIRED_ADMIN_RIGHTS == REQUIRED_ADMIN_RIGHTS =>
            {
                system = true
            }
            Principal::Administrators
                if !admins && ace.mask & REQUIRED_ADMIN_RIGHTS == REQUIRED_ADMIN_RIGHTS =>
            {
                admins = true
            }
            Principal::Service if !service && service_ace_matches(ace.mask, policy) => {
                service = true
            }
            _ => return Err(IdentityDenied),
        }
    }
    if system && admins && service {
        Ok(())
    } else {
        Err(IdentityDenied)
    }
}

/// Allocate/free only the descriptor returned by the official Win32 API.
/// The owner, DACL, and ACE pointers are borrowed while it remains live.
struct OwnedSecurityDescriptor(*mut c_void);
impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: GetSecurityInfo allocates this descriptor with LocalAlloc.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn classify_sid(sid: *mut c_void, service_sid: &[u8]) -> Principal {
    // SAFETY: caller validates the complete inline SID before invoking this.
    unsafe {
        if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
            Principal::LocalSystem
        } else if IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 {
            Principal::Administrators
        } else if EqualSid(sid, service_sid.as_ptr().cast_mut().cast()) != 0 {
            Principal::Service
        } else {
            Principal::Foreign
        }
    }
}

fn inspect_acl(
    file: &File,
    service_sid: &[u8],
    policy: ServiceDaclPolicy,
) -> Result<(), IdentityDenied> {
    let mut owner: *mut c_void = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: *mut c_void = ptr::null_mut();
    // SAFETY: a live std::fs::File owns this handle. Win32 borrows it,
    // and the returned security descriptor is freed by OwnedSecurityDescriptor.
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    let _owned = OwnedSecurityDescriptor(sd);
    if code != 0 || sd.is_null() || owner.is_null() || dacl.is_null() {
        return Err(IdentityDenied);
    }
    // The ACL pointer comes directly from the same live OS descriptor.
    // SID fields are copied only after verified descriptor-relative bounds.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err(IdentityDenied);
    }
    let (mut control, mut revision) = (0u16, 0u32);
    if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(IdentityDenied);
    }
    let mut acl_info: ACL_SIZE_INFORMATION = unsafe { mem::zeroed() };
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
            mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || acl_info.AceCount != 3
    {
        return Err(IdentityDenied);
    }
    let copied =
        unsafe { crate::windows_acl_aces::observe_three_aces(sd, owner, dacl, &acl_info) }?;
    // A service-owned state directory could rewrite its own DACL. Require
    // independently administered SYSTEM/Administrators ownership.
    if !matches!(
        classify_sid(copied.owner_sid.as_ptr().cast_mut().cast(), service_sid),
        Principal::LocalSystem | Principal::Administrators
    ) {
        return Err(IdentityDenied);
    }
    let summaries: Vec<AceSummary> = copied
        .aces
        .iter()
        .map(|ace| AceSummary {
            principal: classify_sid(ace.sid.as_ptr().cast_mut().cast(), service_sid),
            mask: ace.mask,
            flags: ace.flags,
        })
        .collect();
    match policy {
        ServiceDaclPolicy::MutableProtectedState => validate_ace_set(&summaries),
        ServiceDaclPolicy::ReadonlyAdministratorParent => validate_parent_ace_set(&summaries),
    }
}

/// OS-handle volume isolation preflight. A volume serial number is only a
/// necessary discriminator, NOT a trustworthy volume GUID or unique physical
/// storage-origin proof; two independently formatted volumes can collide.
/// The actual Windows root issuer remains disabled pending OS-principal ACL
/// attestation, protected component traversal, filesystem identity and review.
#[derive(Debug, Clone, Copy)]
struct WindowsVolumeBoundary {
    parent_serial: Option<u64>,
    root_serial: Option<u64>,
    parent_attributes: u32,
    root_attributes: u32,
    parent_file_index: Option<[u8; 16]>,
    root_file_index: Option<[u8; 16]>,
}

fn validate_volume_boundary(observed: WindowsVolumeBoundary) -> Result<(), IdentityDenied> {
    let (Some(parent_volume), Some(root_volume)) = (observed.parent_serial, observed.root_serial)
    else {
        return Err(IdentityDenied);
    };
    if parent_volume == 0
        || root_volume == 0
        || parent_volume == root_volume
        || observed.parent_file_index.is_none_or(|id| id == [0; 16])
        || observed.root_file_index.is_none_or(|id| id == [0; 16])
        || observed.parent_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || observed.root_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || observed.parent_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || observed.root_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

// This observation is defined for Windows NTFS semantics only.
// An unrecognized, truncated or malformed kernel-reported FS name must DENY.
fn validate_ntfs_fs_name(name: &[u16]) -> Result<(), IdentityDenied> {
    let end = name
        .iter()
        .position(|&unit| unit == 0)
        .ok_or(IdentityDenied)?;
    if end != 4 || name[end + 1..].iter().any(|&unit| unit != 0) {
        return Err(IdentityDenied);
    }
    if String::from_utf16(&name[..end])
        .map_err(|_| IdentityDenied)?
        .eq_ignore_ascii_case("NTFS")
    {
        Ok(())
    } else {
        Err(IdentityDenied)
    }
}

// A remote filesystem can expose familiar file/volume metadata. Reject
// remote, VSMB and removable devices before interpreting NTFS file identity.
// This local-device observation is still NOT storage-origin attestation.
fn validate_local_disk_device(kind: u32, characteristics: u32) -> Result<(), IdentityDenied> {
    let local_disk = kind == FILE_DEVICE_DISK || kind == FILE_DEVICE_DISK_FILE_SYSTEM;
    let forbidden = FILE_REMOTE_DEVICE | FILE_REMOTE_DEVICE_VSMB | FILE_REMOVABLE_MEDIA;
    if !local_disk || (characteristics & forbidden) != 0 {
        Err(IdentityDenied)
    } else {
        Ok(())
    }
}

fn require_local_disk_device_from_handle(opened: &File) -> Result<(), IdentityDenied> {
    let mut io: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    let mut device: FILE_FS_DEVICE_INFORMATION = unsafe { mem::zeroed() };
    // SAFETY: the File handle stays live throughout this synchronous volume
    // information query. Both output buffers are exclusively borrowed,
    // fixed-size and fully initialized; neither pointer is retained.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            opened.as_raw_handle().cast(),
            &mut io,
            (&mut device as *mut FILE_FS_DEVICE_INFORMATION).cast(),
            mem::size_of::<FILE_FS_DEVICE_INFORMATION>() as u32,
            FileFsDeviceInformation,
        )
    };
    if status != 0 || io.Information != mem::size_of::<FILE_FS_DEVICE_INFORMATION>() {
        return Err(IdentityDenied);
    }
    validate_local_disk_device(device.DeviceType, device.Characteristics)
}

/// Query the actual file system through the same already-open kernel handle.
/// A volume serial or reparse target alone does not establish NTFS semantics.
/// This is necessary evidence only, never an authenticated storage issuer.
fn require_ntfs_volume_from_handle(opened: &File) -> Result<(), IdentityDenied> {
    require_local_disk_device_from_handle(opened)?;
    let mut name = [0u16; 32];
    // SAFETY: the live File owns hFile, and the fixed UTF-16 buffer is
    // exclusively writable for this synchronous Win32 information query.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            opened.as_raw_handle().cast(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if ok == 0 {
        return Err(IdentityDenied);
    }
    validate_ntfs_fs_name(&name)
}

/// Read a full kernel object identity from an owned OS directory handle.
/// This cannot establish custody or an actual namespace parent relationship.
fn from_handle(opened: &File) -> Result<(u64, u32, [u8; 16]), IdentityDenied> {
    require_ntfs_volume_from_handle(opened)?;
    // SAFETY: both fixed-size, zero-initialized Win32 POD buffers are
    // borrowed exclusively by the kernel while the same owned File handle
    // stays open. No raw pointer escapes. Unsupported identity queries
    // DENY; legacy 32/64-bit identifier fallback would truncate ReFS IDs.
    let mut identity: FILE_ID_INFO = unsafe { mem::zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            opened.as_raw_handle().cast(),
            FileIdInfo,
            (&mut identity as *mut FILE_ID_INFO).cast(),
            mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(IdentityDenied);
    }
    let mut attributes: FILE_ATTRIBUTE_TAG_INFO = unsafe { mem::zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            opened.as_raw_handle().cast(),
            FileAttributeTagInfo,
            (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(IdentityDenied);
    }
    Ok((
        identity.VolumeSerialNumber,
        attributes.FileAttributes,
        identity.FileId.Identifier,
    ))
}

/// Require two already-open local NTFS directories to name the same kernel
/// file identity. Their pathname strings and permissions are not sufficient.
/// A matching serial/file ID alone is NOT an OS provisioning or atomicity proof.
pub(crate) fn verify_preopened_same_directory_identity(
    given: &File,
    expected: &File,
) -> Result<(), IdentityDenied> {
    let (given_volume, given_flags, given_id) = from_handle(given)?;
    let (expected_volume, expected_flags, expected_id) = from_handle(expected)?;
    let ordinary_dir =
        |flags| flags & FILE_ATTRIBUTE_DIRECTORY != 0 && flags & FILE_ATTRIBUTE_REPARSE_POINT == 0;
    if given_volume == 0
        || given_id == [0; 16]
        || !ordinary_dir(given_flags)
        || !ordinary_dir(expected_flags)
        || (given_volume, given_id) != (expected_volume, expected_id)
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

/// Compare already-open handles without trusting path strings. This is
/// necessary separation, NOT a Windows authority grant.
pub fn verify_preopened_volume_separation(
    parent: &File,
    root: &File,
) -> Result<(), IdentityDenied> {
    let (pvol, pattrs, pidx) = from_handle(parent)?;
    let (rvol, rattrs, ridx) = from_handle(root)?;
    validate_volume_boundary(WindowsVolumeBoundary {
        parent_serial: Some(pvol),
        root_serial: Some(rvol),
        parent_attributes: pattrs,
        root_attributes: rattrs,
        parent_file_index: Some(pidx),
        root_file_index: Some(ridx),
    })
}

/// Verify that the root kernel handle currently resolves from exactly one
/// named entry under the already-open administrative parent handle.
///
/// NtCreateFile(RootDirectory) performs a real kernel-relative open; no
/// ambient path is reconstructed. The final NTFS volume mountpoint must
/// resolve normally (FILE_OPEN_REPARSE_POINT would open the link itself).
/// The reopened object must have the exact same 64-bit volume + 128-bit
/// file identity as the protected root handle. When the last component
/// is a reparse point, a separate handle-relative FSCTL query additionally
/// requires a true Volume{GUID} root, never a directory junction target.
/// These are sequential INSTANT observations, not an atomic origin proof,
/// concurrency guarantee or authorization to perform filesystem I/O.
pub fn verify_preopened_named_child_identity(
    parent: &File,
    root: &File,
    child: &str,
) -> Result<(), IdentityDenied> {
    verify_preopened_child_identity(parent, root, child, ChildEntryResolution::FollowMountRoot)?;
    crate::windows_mountpoint::verify_named_volume_mount_entry(parent, child)
}

/// Observe whether an opened administrator-controlled child is exactly
/// the ordinary directory entry named by a pinned parent. Unlike the mounted
/// isolated-root lookup, the final component is opened with
/// FILE_OPEN_REPARSE_POINT: junctions and other reparse entries are denied
/// without following them, even if the opened target has matching file ID.
///
/// This is a point-in-time, non-issuing primitive. It does not authenticate
/// the parent handle, the complete ancestor chain, or concurrent custody.
pub fn verify_preopened_administrative_child_identity(
    administrative_ancestor: &File,
    administrative_child: &File,
    child_name: &str,
) -> Result<(), IdentityDenied> {
    verify_preopened_child_identity(
        administrative_ancestor,
        administrative_child,
        child_name,
        ChildEntryResolution::OpenEntryItself,
    )
}

/// Inspect *every* named, opened administrative directory entry from
/// an independently pinned anchor. Each step forbids following the final
/// component's reparse point and checks complete OS file-object identity.
///
/// The caller must separately authenticate the anchor's actual provenance
/// and OS principal. This snapshot is NOT atomic across the steps, does not
/// convey I/O authority, and cannot be used as a durable storage grant.
pub fn verify_preopened_administrative_chain(
    anchor: &File,
    chain: &[(&File, &str)],
) -> Result<(), IdentityDenied> {
    if chain.is_empty() {
        return Err(IdentityDenied);
    }
    let mut parent = anchor;
    for &(child, child_name) in chain {
        verify_preopened_administrative_child_identity(parent, child, child_name)?;
        parent = child;
    }
    Ok(())
}

/// A revocable, non-issuing observation of an independently supplied OS
/// directory handle and its complete supplied administrative child chain.
///
/// This value does not authenticate the origin or ACL of the anchor, grant
/// filesystem operations, or make verification atomic with later I/O.
/// Revalidation is point-in-time. Once any verification fails (or panics),
/// the observation remains revoked even if the namespace is restored.
pub struct ObservedWindowsAdministrativeChain {
    anchor: File,
    entries: Vec<(File, String)>,
    active: bool,
}

impl ObservedWindowsAdministrativeChain {
    /// Pin each supplied object before a second, handle-relative verification.
    /// This is not a policy issuer; callers still must prove anchor custody.
    pub fn observe(anchor: &File, chain: &[(&File, &str)]) -> Result<Self, IdentityDenied> {
        if chain.is_empty() || chain.len() > 64 {
            return Err(IdentityDenied);
        }
        verify_preopened_administrative_chain(anchor, chain)?;
        let mut entries = Vec::with_capacity(chain.len());
        for &(child, name) in chain {
            entries.push((
                child.try_clone().map_err(|_| IdentityDenied)?,
                name.to_owned(),
            ));
        }
        let mut observation = Self {
            anchor: anchor.try_clone().map_err(|_| IdentityDenied)?,
            entries,
            active: true,
        };
        observation.revalidate()?;
        Ok(observation)
    }

    /// Never re-admit a failed observation, including after a panic/unwind.
    pub fn revalidate(&mut self) -> Result<(), IdentityDenied> {
        if !self.active {
            return Err(IdentityDenied);
        }
        self.active = false;
        let chain: Vec<_> = self
            .entries
            .iter()
            .map(|(child, name)| (child, name.as_str()))
            .collect();
        verify_preopened_administrative_chain(&self.anchor, &chain)?;
        self.active = true;
        Ok(())
    }
}

enum ChildEntryResolution {
    FollowMountRoot,
    OpenEntryItself,
}

fn verify_preopened_child_identity(
    parent: &File,
    root: &File,
    child: &str,
    resolution: ChildEntryResolution,
) -> Result<(), IdentityDenied> {
    use std::os::windows::io::FromRawHandle;

    // Strictly one component, no device aliases, NT stream syntax, dot,
    // separators, Unicode normalization or client-supplied traversals.
    let valid = !child.is_empty()
        && child.len() <= 64
        && child
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && !matches!(
            child.to_ascii_uppercase().as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        );
    if !valid {
        return Err(IdentityDenied);
    }
    let mut wide: Vec<u16> = child.encode_utf16().collect();
    let bytes = u16::try_from(wide.len().saturating_mul(2)).map_err(|_| IdentityDenied)?;
    let native_name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle().cast(),
        ObjectName: &native_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle = ptr::null_mut();
    let mut status_block: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
    // SAFETY: all input buffers and the owning parent File remain alive for
    // this synchronous, open-existing kernel call. The returned HANDLE is
    // immediately adopted by File for exactly-once close, including failures
    // of subsequent identity reads. No client-controlled path is consulted.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_READ_ATTRIBUTES,
            &attributes,
            &mut status_block,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE
                | match resolution {
                    ChildEntryResolution::FollowMountRoot => 0,
                    ChildEntryResolution::OpenEntryItself => FILE_OPEN_REPARSE_POINT,
                },
            ptr::null(),
            0,
        )
    };
    if status < 0 || handle.is_null() || handle as isize == -1 {
        return Err(IdentityDenied);
    }
    let relative = unsafe { File::from_raw_handle(handle) };
    let (volume, flags, object) = from_handle(&relative)?;
    let (expected_volume, expected_flags, expected_object) = from_handle(root)?;
    if volume == 0
        || object == [0; 16]
        || flags & FILE_ATTRIBUTE_DIRECTORY == 0
        || flags & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || expected_flags & FILE_ATTRIBUTE_DIRECTORY == 0
        || expected_flags & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (volume, object) != (expected_volume, expected_object)
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

/// Data-only observer. It requires the current *kernel* process token to be
/// the dedicated SCM service identity before looking at any supplied handle.
/// Its caller must independently acquire the state directory via protected,
/// component-pinned bootstrap. This function cannot perform that bootstrap.
pub fn observe_preopened_service_state(
    file: File,
) -> Result<ObservedWindowsStateDirectory, IdentityDenied> {
    verify_service_identity()?;
    require_ntfs_volume_from_handle(&file)?;
    let attrs = file.metadata().map_err(|_| IdentityDenied)?;
    if !attrs.is_dir() || attrs.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(IdentityDenied);
    }
    let service_sid = crate::windows_token::service_sid_bytes().map_err(|_| IdentityDenied)?;
    inspect_acl(
        &file,
        &service_sid,
        ServiceDaclPolicy::MutableProtectedState,
    )?;
    Ok(ObservedWindowsStateDirectory { file })
}

/// Non-issuing Windows storage-root observation. A caller may only supply
/// ALREADY OPENED directory handles; neither the current process token nor
/// ACL can be provided as arguments. First require the real SCM service
/// identity and the protected DACL of the root, then deny same-volume
/// storage. This is a necessary preflight, not an independently approved
/// Windows issuer: the parent/child relationship, unique volume provenance,
/// mount aliases, race-free pinning and durable authority are still missing.
///
/// The legacy root-only observer is intentionally not accessible to downstream
/// consumers: it bypasses independently bound ProgramData/HKLM provenance.
///
/// ```compile_fail
/// use jdc_authority_service::windows_policy_root::observe_preopened_isolated_service_root;
/// let _untrusted_root_only_admission = observe_preopened_isolated_service_root;
/// ```
pub(crate) fn observe_preopened_isolated_service_root(
    parent: &File,
    root: File,
    child_name: &str,
) -> Result<ObservedWindowsIsolatedRoot, IdentityDenied> {
    let root = observe_preopened_service_state(root)?;
    let service_sid = crate::windows_token::service_sid_bytes().map_err(|_| IdentityDenied)?;
    inspect_acl(
        parent,
        &service_sid,
        ServiceDaclPolicy::ReadonlyAdministratorParent,
    )?;
    verify_preopened_volume_separation(parent, &root.file)?;
    verify_preopened_named_child_identity(parent, &root.file, child_name)?;
    let mut observation = ObservedWindowsIsolatedRoot {
        parent: parent.try_clone().map_err(|_| IdentityDenied)?,
        root,
        child_name: child_name.to_owned(),
        active: true,
    };
    // Check again after duplicating the parent handle. No result from this
    // admission is an I/O grant; later use requires fresh revalidation.
    observation.revalidate()?;
    Ok(observation)
}

/// Debug-only, non-authorizing SCM control: preserve a genuine OS comparison
/// with the legacy root-only gate, but never expose the weaker observer type,
/// retained handles, or a usable grant outside this crate. The release
/// diagnostic is permanently DENY and never evaluates the weaker observer.
#[cfg(debug_assertions)]
pub fn debug_validate_legacy_isolated_root_without_issuer(
    parent: &File,
    root: File,
    child_name: &str,
) -> Result<(), IdentityDenied> {
    let mut observed = observe_preopened_isolated_service_root(parent, root, child_name)?;
    observed.revalidate()
}

/// Debug diagnostics have no operational authority in a release build.
/// The symbol remains shape-compatible for the non-shipping test example,
/// but the weaker gate is never evaluated here.
#[cfg(not(debug_assertions))]
pub fn debug_validate_legacy_isolated_root_without_issuer(
    _parent: &File,
    _root: File,
    _child_name: &str,
) -> Result<(), IdentityDenied> {
    Err(IdentityDenied)
}

/// Non-issuing root observation: the named source-parent/anchor entry,
/// complete administrative chain, and isolated root are pinned and revalidated.
/// This type exposes no filesystem operation or reusable root File handle.
///
/// The source parent must match OS-known ProgramData by opened-object identity,
/// and the anchor child name must equal the fixed protected-HKLM policy
/// witness. This still cannot establish atomic I/O or exclusive storage custody.
pub struct ObservedWindowsChainBoundIsolatedRoot {
    anchor_parent: File,
    anchor_name: String,
    administrative: ObservedWindowsAdministrativeChain,
    isolated: ObservedWindowsIsolatedRoot,
    active: bool,
}

impl ObservedWindowsChainBoundIsolatedRoot {
    /// Check the actual SCM token, protected administrative DACLs, every
    /// pinned ancestor edge, then the isolated root's own kernel/ACL gates.
    /// Any failure or unwind permanently revokes this joint observation.
    pub fn revalidate(&mut self) -> Result<(), IdentityDenied> {
        if !self.active {
            return Err(IdentityDenied);
        }
        self.active = false;
        verify_service_identity()?;
        crate::windows_program_data_origin::verify_system_program_data_parent(&self.anchor_parent)?;
        if crate::windows_epoch_anchor::observe_fixed_source_anchor_name()? != self.anchor_name {
            return Err(IdentityDenied);
        }
        verify_preopened_administrative_child_identity(
            &self.anchor_parent,
            &self.administrative.anchor,
            &self.anchor_name,
        )?;
        let sid = crate::windows_token::service_sid_bytes().map_err(|_| IdentityDenied)?;
        inspect_acl(
            &self.administrative.anchor,
            &sid,
            ServiceDaclPolicy::ReadonlyAdministratorParent,
        )?;
        for (entry, _) in &self.administrative.entries {
            inspect_acl(entry, &sid, ServiceDaclPolicy::ReadonlyAdministratorParent)?;
        }
        self.administrative.revalidate()?;
        self.isolated.revalidate()?;
        self.active = true;
        Ok(())
    }

    // Kernel-only fixture: does not authenticate an SCM principal/ACL,
    // segregated volume, or administrative anchor and cannot issue I/O.
    #[cfg(test)]
    fn from_preopened_kernel_fixture(
        anchor_parent: &File,
        anchor_name: &str,
        anchor: &File,
        chain: &[(&File, &str)],
        root: File,
        root_name: &str,
    ) -> Result<Self, IdentityDenied> {
        verify_preopened_administrative_child_identity(anchor_parent, anchor, anchor_name)?;
        let administrative = ObservedWindowsAdministrativeChain::observe(anchor, chain)?;
        let &(parent, _) = chain.last().ok_or(IdentityDenied)?;
        let isolated =
            ObservedWindowsIsolatedRoot::from_preopened_kernel_fixture(parent, root, root_name)?;
        let mut observed = Self {
            anchor_parent: anchor_parent.try_clone().map_err(|_| IdentityDenied)?,
            anchor_name: anchor_name.to_owned(),
            administrative,
            isolated,
            active: true,
        };
        observed.revalidate_kernel_only_for_test()?;
        Ok(observed)
    }

    #[cfg(test)]
    fn revalidate_kernel_only_for_test(&mut self) -> Result<(), IdentityDenied> {
        if !self.active {
            return Err(IdentityDenied);
        }
        self.active = false;
        verify_preopened_administrative_child_identity(
            &self.anchor_parent,
            &self.administrative.anchor,
            &self.anchor_name,
        )?;
        self.administrative.revalidate()?;
        self.isolated.revalidate_kernel_binding_only_for_test()?;
        self.active = true;
        Ok(())
    }
}

/// Non-issuing authenticated-process preflight for a mounted isolated root.
/// The parent of the mounted root is selected ONLY as the final pinned
/// administrative-chain entry, not from an unrelated supplied handle.
///
/// This verifies the real SCM principal, protected per-ancestor ACLs and the
/// source-parent/anchor edge, and OS-known ProgramData parent identity.
/// The registry witness binds the named anchor under OS-known ProgramData;
/// it does not prove durable/exclusive storage custody or I/O atomicity.
/// Not an MCP backend/grant.
pub fn observe_preopened_chain_bound_isolated_service_root(
    anchor_parent: &File,
    anchor_name: &str,
    anchor: &File,
    chain: &[(&File, &str)],
    root: File,
    root_name: &str,
) -> Result<ObservedWindowsChainBoundIsolatedRoot, IdentityDenied> {
    verify_service_identity()?;
    crate::windows_program_data_origin::verify_system_program_data_parent(anchor_parent)?;
    if crate::windows_epoch_anchor::observe_fixed_source_anchor_name()? != anchor_name {
        return Err(IdentityDenied);
    }
    verify_preopened_administrative_child_identity(anchor_parent, anchor, anchor_name)?;
    let sid = crate::windows_token::service_sid_bytes().map_err(|_| IdentityDenied)?;
    inspect_acl(anchor, &sid, ServiceDaclPolicy::ReadonlyAdministratorParent)?;
    for &(entry, _) in chain {
        inspect_acl(entry, &sid, ServiceDaclPolicy::ReadonlyAdministratorParent)?;
    }
    let administrative = ObservedWindowsAdministrativeChain::observe(anchor, chain)?;
    let &(parent, _) = chain.last().ok_or(IdentityDenied)?;
    let isolated = observe_preopened_isolated_service_root(parent, root, root_name)?;
    let mut observed = ObservedWindowsChainBoundIsolatedRoot {
        anchor_parent: anchor_parent.try_clone().map_err(|_| IdentityDenied)?,
        anchor_name: anchor_name.to_owned(),
        administrative,
        isolated,
        active: true,
    };
    observed.revalidate()?;
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_known_program_data_parent_must_reject_caller_substitution() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let known = std::env::var_os("ProgramData")
            .expect("Windows hosted test must expose the system common-data path");
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .expect("actual directory open")
        };
        let genuine = open(std::path::Path::new(&known));
        let foreign_fixture = tempfile::tempdir().expect("disposable negative control");
        let substituted = open(foreign_fixture.path());
        assert_eq!(
            crate::windows_program_data_origin::verify_system_program_data_parent(&genuine),
            Ok(()),
            "OS-known ProgramData must remain usable as the non-issuing source parent"
        );
        assert_eq!(
            crate::windows_program_data_origin::verify_system_program_data_parent(&substituted),
            Err(IdentityDenied),
            "a legitimate-looking but independently supplied parent cannot replace ProgramData"
        );
    }

    #[test]
    fn windows_root_identity_must_be_bound_to_kernel_reported_ntfs() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().expect("disposable Windows fixture");
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(BACKUP_SEMANTICS)
            .open(fixture.path())
            .expect("open a real Windows directory handle");
        assert_eq!(
            require_ntfs_volume_from_handle(&directory),
            Ok(()),
            "host fixture must reside on real NTFS; never score unknown FS as accepted"
        );
        for other in ["ReFS", "FAT32", "exFAT", "SMB", "", "NTFS\0MALICIOUS"] {
            let raw = other
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            assert_eq!(
                validate_ntfs_fs_name(&raw),
                Err(IdentityDenied),
                "unreviewed filesystem names must never pass the NTFS-only observer"
            );
        }
        let valid = "NTFS"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        assert_eq!(validate_ntfs_fs_name(&valid), Ok(()));
    }

    #[test]
    fn windows_root_requires_kernel_local_disk_device_evidence() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().expect("disposable Windows fixture");
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(BACKUP_SEMANTICS)
            .open(fixture.path())
            .expect("open a real directory handle");
        assert_eq!(
            require_local_disk_device_from_handle(&dir),
            Ok(()),
            "real local NTFS fixture must pass kernel device classification"
        );
        for kind in [0, 1, 2, 3, 9, 0xffff_ffff] {
            assert_eq!(validate_local_disk_device(kind, 0), Err(IdentityDenied));
        }
        for kind in [7, 8] {
            assert_eq!(validate_local_disk_device(kind, 0x20), Ok(()));
            for characteristic in [0x01, 0x10, 0x80000, 0x80011] {
                assert_eq!(
                    validate_local_disk_device(kind, characteristic),
                    Err(IdentityDenied),
                    "remote or removable device must never pass through NTFS label alone"
                );
            }
        }
    }

    fn ace(principal: Principal, mask: u32) -> AceSummary {
        AceSummary {
            principal,
            mask,
            flags: REQUIRED_ACE_FLAGS,
        }
    }
    fn legitimate() -> Vec<AceSummary> {
        vec![
            ace(Principal::LocalSystem, 0x001f01ff),
            ace(Principal::Administrators, 0x001f01ff),
            ace(Principal::Service, 0x000301bf),
        ]
    }
    #[test]
    fn exact_three_principals_accept_and_unexpected_principals_deny() {
        assert_eq!(validate_ace_set(&legitimate()), Ok(()));
        for principal in [
            Principal::Foreign,
            Principal::LocalSystem,
            Principal::Administrators,
        ] {
            let mut entries = legitimate();
            entries[2].principal = principal;
            assert_eq!(validate_ace_set(&entries), Err(IdentityDenied));
        }
        let mut extra = legitimate();
        extra.push(ace(Principal::Foreign, 1));
        assert_eq!(validate_ace_set(&extra), Err(IdentityDenied));
    }
    #[test]
    fn service_can_never_own_dacl_or_owner_permissions() {
        for prohibited in [WRITE_DAC, WRITE_OWNER, GENERIC_ALL] {
            let mut entries = legitimate();
            entries[2].mask |= prohibited;
            assert_eq!(validate_ace_set(&entries), Err(IdentityDenied));
        }
        let mut inherited = legitimate();
        inherited[0].flags = 0x10;
        assert_eq!(validate_ace_set(&inherited), Err(IdentityDenied));
    }
    #[test]
    fn unprivileged_or_noninheriting_state_dacl_is_denied() {
        let mut weak_system = legitimate();
        weak_system[0].mask = 0x0002_0000; // READ_CONTROL alone is not FullControl.
        assert_eq!(validate_ace_set(&weak_system), Err(IdentityDenied));

        let mut weak_admin = legitimate();
        weak_admin[1].mask = 0x0002_0000;
        assert_eq!(validate_ace_set(&weak_admin), Err(IdentityDenied));

        let mut weak_service = legitimate();
        weak_service[2].mask = 0x0002_0000;
        assert_eq!(validate_ace_set(&weak_service), Err(IdentityDenied));

        for principal in 0..3 {
            let mut no_file_inheritance = legitimate();
            no_file_inheritance[principal].flags = 0x02; // Container only.
            assert_eq!(
                validate_ace_set(&no_file_inheritance),
                Err(IdentityDenied),
                "missing file-inheritance on ACE index {principal}"
            );
            let mut no_directory_inheritance = legitimate();
            no_directory_inheritance[principal].flags = 0x01; // Object only.
            assert_eq!(
                validate_ace_set(&no_directory_inheritance),
                Err(IdentityDenied),
                "missing container-inheritance on ACE index {principal}"
            );
        }
    }

    #[test]
    fn administrative_mount_parent_allows_service_traversal_but_never_mutation() {
        let mut parent = legitimate();
        parent[2].mask = 0x0002_00a9; // NTFS ReadAndExecute
        assert_eq!(validate_parent_ace_set(&parent), Ok(()));
        parent[2].mask |= 0x0010_0000; // SYNCHRONIZE
        assert_eq!(validate_parent_ace_set(&parent), Ok(()));
        for extra in [
            0x0000_0002, // FILE_WRITE_DATA / FILE_ADD_FILE
            0x0000_0004, // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
            0x0001_0000, // DELETE
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_ALL,
        ] {
            let mut untrusted = parent.clone();
            untrusted[2].mask |= extra;
            assert_eq!(
                validate_parent_ace_set(&untrusted),
                Err(IdentityDenied),
                "parent became mutable through service ACE bit {extra:#x}"
            );
        }
        let mut missing_traverse = parent.clone();
        missing_traverse[2].mask &= !0x0000_0020; // FILE_TRAVERSE
        assert_eq!(
            validate_parent_ace_set(&missing_traverse),
            Err(IdentityDenied)
        );
        let mut foreign = parent.clone();
        foreign.push(ace(Principal::Foreign, 1));
        assert_eq!(validate_parent_ace_set(&foreign), Err(IdentityDenied));
    }

    #[test]
    fn distinct_volume_admission_denies_unavailable_equal_or_untrusted_metadata() {
        let valid = WindowsVolumeBoundary {
            parent_serial: Some(0x1234),
            root_serial: Some(0x5678),
            parent_attributes: 0x10,
            root_attributes: 0x10,
            parent_file_index: Some([4; 16]),
            root_file_index: Some([9; 16]),
        };
        assert_eq!(validate_volume_boundary(valid), Ok(()));
        for rejected in [
            WindowsVolumeBoundary {
                root_serial: valid.parent_serial,
                ..valid
            },
            WindowsVolumeBoundary {
                parent_serial: None,
                ..valid
            },
            WindowsVolumeBoundary {
                root_serial: None,
                ..valid
            },
            WindowsVolumeBoundary {
                parent_serial: Some(0),
                ..valid
            },
            WindowsVolumeBoundary {
                root_serial: Some(0),
                ..valid
            },
            WindowsVolumeBoundary {
                root_attributes: valid.root_attributes | FILE_ATTRIBUTE_REPARSE_POINT,
                ..valid
            },
            WindowsVolumeBoundary {
                parent_attributes: valid.parent_attributes | FILE_ATTRIBUTE_REPARSE_POINT,
                ..valid
            },
            WindowsVolumeBoundary {
                root_attributes: 0,
                ..valid
            },
            WindowsVolumeBoundary {
                parent_attributes: 0,
                ..valid
            },
            WindowsVolumeBoundary {
                parent_file_index: None,
                ..valid
            },
            WindowsVolumeBoundary {
                root_file_index: None,
                ..valid
            },
            WindowsVolumeBoundary {
                root_file_index: Some([0; 16]),
                ..valid
            },
            WindowsVolumeBoundary {
                parent_file_index: Some([0; 16]),
                ..valid
            },
        ] {
            assert_eq!(validate_volume_boundary(rejected), Err(IdentityDenied));
        }
    }

    #[test]
    fn full_kernel_volume_and_file_ids_reject_truncated_or_missing_identity() {
        // Two 64-bit volume IDs may share their lower 32 bits. The legacy
        // BY_HANDLE_FILE_INFORMATION projection cannot represent this case.
        let high_bits_differ = WindowsVolumeBoundary {
            parent_serial: Some(0x0000_0001_aabb_ccdd),
            root_serial: Some(0x0000_0002_aabb_ccdd),
            parent_attributes: FILE_ATTRIBUTE_DIRECTORY,
            root_attributes: FILE_ATTRIBUTE_DIRECTORY,
            parent_file_index: Some([0x01; 16]),
            root_file_index: Some([0x02; 16]),
        };
        assert_eq!(validate_volume_boundary(high_bits_differ), Ok(()));
        // ReFS may legitimately use bits 64..127 of FILE_ID_128. The
        // historical 64-bit file-index projection cannot represent this
        // nonzero object ID, but the kernel's full identifier can.
        let mut high_only_file_id = [0u8; 16];
        high_only_file_id[15] = 0x80;
        assert_eq!(
            validate_volume_boundary(WindowsVolumeBoundary {
                root_file_index: Some(high_only_file_id),
                ..high_bits_differ
            }),
            Ok(()),
            "valid high-half-only file identity must not be truncated or denied"
        );
        assert_eq!(
            validate_volume_boundary(WindowsVolumeBoundary {
                root_serial: high_bits_differ.parent_serial,
                ..high_bits_differ
            }),
            Err(IdentityDenied)
        );
        for absent in [
            WindowsVolumeBoundary {
                parent_file_index: Some([0; 16]),
                ..high_bits_differ
            },
            WindowsVolumeBoundary {
                root_file_index: Some([0; 16]),
                ..high_bits_differ
            },
        ] {
            assert_eq!(validate_volume_boundary(absent), Err(IdentityDenied));
        }
    }

    #[test]
    fn real_windows_root_relative_child_identity_requires_exact_parent_and_name() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let parent_path = fixture.path().join("actual-parent");
        let foreign_parent_path = fixture.path().join("foreign-parent");
        let child_path = parent_path.join("isolated");
        let foreign_child_path = foreign_parent_path.join("isolated");
        std::fs::create_dir(&parent_path).unwrap();
        std::fs::create_dir(&foreign_parent_path).unwrap();
        std::fs::create_dir(&child_path).unwrap();
        std::fs::create_dir(&foreign_child_path).unwrap();
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let parent = open(&parent_path);
        let foreign_parent = open(&foreign_parent_path);
        let child = open(&child_path);
        let foreign_child = open(&foreign_child_path);
        assert_eq!(
            verify_preopened_named_child_identity(&parent, &child, "isolated"),
            Ok(()),
            "exact direct child must be accepted independently of volume isolation"
        );
        assert_eq!(
            verify_preopened_named_child_identity(&foreign_parent, &child, "isolated"),
            Err(IdentityDenied),
            "a protected but unrelated parent must not authorize this root handle"
        );
        assert_eq!(
            verify_preopened_named_child_identity(&parent, &foreign_child, "isolated"),
            Err(IdentityDenied),
            "a replacement root object must not be accepted by its pathname"
        );
        for rejected in [
            "",
            ".",
            "..",
            "other",
            "isolated/child",
            "../isolated",
            "isolated\\child",
            "isolated:stream",
            "isolated.",
            "isolated ",
            "CON",
        ] {
            assert_eq!(
                verify_preopened_named_child_identity(&parent, &child, rejected),
                Err(IdentityDenied),
                "unsafe or wrong direct component {rejected:?} must be denied"
            );
        }
    }

    #[test]
    fn windows_replaced_child_does_not_validate_stale_root_handle() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let root_path = fixture.path().join("isolated");
        let retired_path = fixture.path().join("original-retired");
        std::fs::create_dir(&root_path).unwrap();
        let sentinel = root_path.join("sentinel.bin");
        std::fs::write(&sentinel, b"ORIGINAL_UNCHANGED_BYTES").unwrap();
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let parent = open(fixture.path());
        let initially_authorized = open(&root_path);
        assert_eq!(
            verify_preopened_named_child_identity(&parent, &initially_authorized, "isolated"),
            Ok(()),
            "positive witness must pass before substitution"
        );
        std::fs::rename(&root_path, &retired_path)
            .expect("actual NTFS rename of an opened directory must be exercised");
        std::fs::create_dir(&root_path).unwrap();
        let replacement = open(&root_path);
        assert_eq!(
            verify_preopened_named_child_identity(&parent, &initially_authorized, "isolated"),
            Err(IdentityDenied),
            "a previously opened root must not be authorized after its name changes object"
        );
        assert_eq!(
            verify_preopened_named_child_identity(&parent, &replacement, "isolated"),
            Ok(()),
            "a newly opened matching root still passes the snapshot identity check"
        );
        assert_eq!(
            std::fs::read(retired_path.join("sentinel.bin")).unwrap(),
            b"ORIGINAL_UNCHANGED_BYTES"
        );
        assert!(!root_path.join("sentinel.bin").exists());
    }

    #[test]
    fn real_same_volume_directory_handles_never_pass_isolation_preflight() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let child = fixture.path().join("root");
        std::fs::create_dir(&child).unwrap();
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(BACKUP_SEMANTICS)
            .open(fixture.path())
            .unwrap();
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(BACKUP_SEMANTICS)
            .open(&child)
            .unwrap();
        assert_eq!(
            verify_preopened_volume_separation(&parent, &opened),
            Err(IdentityDenied),
            "same-volume NTFS handles must not become an isolated root"
        );
    }

    #[test]
    #[ignore = "requires a disposable, separately attached NTFS VHD under hosted acceptance"]
    fn real_distinct_ntfs_vhd_handles_pass_non_authorizing_volume_preflight() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let parent_path = std::env::var_os("JDC_T011_WINDOWS_VHD_PARENT")
            .expect("the disposable parent on the system disk is mandatory");
        let volume_path = std::env::var_os("JDC_T011_WINDOWS_VHD_ROOT")
            .expect("the independent NTFS VHD volume root is mandatory");
        let open_dir = |path: &std::ffi::OsStr| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .expect("a real already-open directory handle is required")
        };
        let parent = open_dir(&parent_path);
        let separate = open_dir(&volume_path);
        assert_eq!(
            verify_preopened_volume_separation(&parent, &separate),
            Ok(()),
            "a real separately formatted NTFS volume must be distinguishable"
        );
        assert_eq!(
            verify_preopened_volume_separation(&separate, &separate),
            Err(IdentityDenied),
            "two handles to the same VHD must never pass isolation"
        );
        assert_eq!(
            verify_preopened_volume_separation(&parent, &parent),
            Err(IdentityDenied),
            "two handles to the system volume must never pass isolation"
        );
    }

    #[test]
    fn interrupted_windows_root_revalidation_must_poison_observation_before_unwind() {
        use std::{
            os::windows::fs::OpenOptionsExt,
            panic::{catch_unwind, AssertUnwindSafe},
        };
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let child = fixture.path().join("isolated");
        std::fs::create_dir(&child).unwrap();
        let open = |p: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(p)
                .unwrap()
        };
        let parent = open(fixture.path());
        let mut observed = ObservedWindowsIsolatedRoot::from_preopened_kernel_fixture(
            &parent,
            open(&child),
            "isolated",
        )
        .unwrap();
        assert_eq!(observed.revalidate_kernel_binding_only_for_test(), Ok(()));
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            let _ = observed.revalidate_or_revoke(|_| -> Result<(), IdentityDenied> {
                panic!("simulated interruption before the kernel recheck returns");
            });
        }));
        assert!(
            interrupted.is_err(),
            "the test must actually exercise unwind"
        );
        assert_eq!(
            observed.revalidate_kernel_binding_only_for_test(),
            Err(IdentityDenied),
            "an interrupted security check must never leave the old observation reusable"
        );
        assert!(
            child.is_dir(),
            "the fixture never mutates the authorized root"
        );
    }

    #[test]
    fn observed_isolated_root_revocation_survives_rename_restore_on_real_ntfs() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let root_path = fixture.path().join("isolated");
        let moved = fixture.path().join("moved-original");
        let replacement = fixture.path().join("replacement");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::write(root_path.join("canary.bin"), b"UNCHANGED_OUTSIDE_SENTINEL").unwrap();
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let parent = open(fixture.path());
        let root = open(&root_path);
        // This constructor exists only in unit tests. It cannot authenticate
        // an SCM principal, issue a grant or bypass the production gate.
        let mut observed =
            ObservedWindowsIsolatedRoot::from_preopened_kernel_fixture(&parent, root, "isolated")
                .expect("real direct-child precondition must hold");
        assert_eq!(observed.revalidate_kernel_binding_only_for_test(), Ok(()));
        std::fs::rename(&root_path, &moved)
            .expect("actual filesystem rename must be possible under the test principal");
        std::fs::create_dir(&root_path).unwrap();
        assert_eq!(
            observed.revalidate_kernel_binding_only_for_test(),
            Err(IdentityDenied),
            "a different object behind the original name must permanently revoke"
        );
        std::fs::rename(&root_path, &replacement).unwrap();
        std::fs::rename(&moved, &root_path).unwrap();
        assert_eq!(
            observed.revalidate_kernel_binding_only_for_test(),
            Err(IdentityDenied),
            "restoring the old name must not restore a revoked observation"
        );
        assert_eq!(
            std::fs::read(root_path.join("canary.bin")).unwrap(),
            b"UNCHANGED_OUTSIDE_SENTINEL"
        );
        assert!(!replacement.join("canary.bin").exists());
    }

    #[test]
    #[ignore = "manual Windows-host acceptance requires a second distinct NTFS volume"]
    fn real_cross_volume_directory_junction_is_not_a_volume_mount() {
        use std::{os::windows::fs::OpenOptionsExt, process::Command};
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let parent = open(fixture.path());
        let foreign = ["D:\\", "E:\\"]
            .iter()
            .find_map(|drive| {
                let root = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(BACKUP_SEMANTICS)
                    .open(drive)
                    .ok()?;
                verify_preopened_volume_separation(&parent, &root)
                    .is_ok()
                    .then(|| (drive.to_string(), root))
            })
            .expect("manual acceptance requires another real, accessible NTFS volume");
        let alias = fixture.path().join("isolated");
        let created = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&alias)
            .arg(&foreign.0)
            .output()
            .unwrap();
        assert!(
            created.status.success(),
            "disposable NTFS junction must exist: {created:?}"
        );
        let target = open(&alias);
        let same_target = from_handle(&target).unwrap() == from_handle(&foreign.1).unwrap();
        let separate_volume = verify_preopened_volume_separation(&parent, &target);
        let final_entry = verify_preopened_named_child_identity(&parent, &target, "isolated");
        // Only remove the local junction entry; the foreign volume is never modified.
        std::fs::remove_dir(&alias).expect("local disposable junction cleanup must succeed");
        assert!(
            same_target,
            "fixture must actually resolve to foreign volume root"
        );
        assert_eq!(
            separate_volume,
            Ok(()),
            "cross-volume gate must pass before type denial"
        );
        assert_eq!(
            final_entry,
            Err(IdentityDenied),
            "cross-volume junction is not a mountpoint"
        );
    }

    #[test]
    #[ignore = "manual Windows-host acceptance requires a second distinct NTFS volume"]
    fn real_volume_guid_root_mountpoint_passes_nonissuing_kernel_preflight() {
        use std::{os::windows::fs::OpenOptionsExt, process::Command};
        use windows_sys::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let mut root_name: Vec<u16> = "D:\\".encode_utf16().collect();
        root_name.push(0);
        let mut guid_name = [0u16; 64];
        let ok = unsafe {
            GetVolumeNameForVolumeMountPointW(
                root_name.as_ptr(),
                guid_name.as_mut_ptr(),
                guid_name.len() as u32,
            )
        };
        assert_ne!(
            ok, 0,
            "this manual test requires an accessible D: volume GUID"
        );
        let nul = guid_name.iter().position(|&code| code == 0).unwrap();
        let volume_guid = String::from_utf16(&guid_name[..nul]).unwrap();
        let alias = fixture.path().join("isolated");
        let linked = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&alias)
            .arg(&volume_guid)
            .output()
            .unwrap();
        assert!(
            linked.status.success(),
            "disposable volume-root entry must exist: {linked:?}"
        );
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let parent = open(fixture.path());
        let mounted_root = open(&alias);
        let physical_root = open(std::path::Path::new("D:\\"));
        let same_root = from_handle(&mounted_root).unwrap() == from_handle(&physical_root).unwrap();
        let separate = verify_preopened_volume_separation(&parent, &mounted_root);
        let admissible = verify_preopened_named_child_identity(&parent, &mounted_root, "isolated");
        std::fs::remove_dir(&alias).expect("remove only the temporary volume GUID entry");
        assert!(same_root, "opened target must be the physical D: root");
        assert_eq!(separate, Ok(()), "real second volume must be isolated");
        assert_eq!(
            admissible,
            Ok(()),
            "real volume GUID root must remain admissible"
        );
    }

    #[test]
    fn admin_ancestor_verifier_denies_live_junction_to_outside_even_when_kernel_ids_match() {
        use std::{os::windows::fs::OpenOptionsExt, process::Command};
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let admin = fixture.path().join("admin");
        let normal = admin.join("ordinary-parent");
        let alias = admin.join("alias-parent");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&admin).unwrap();
        std::fs::create_dir(&normal).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let sentinel = outside.join("sentinel.bin");
        std::fs::write(&sentinel, b"OUTSIDE_BYTES_NEVER_CHANGED").unwrap();
        let open = |p: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(p)
                .unwrap()
        };
        let anchor = open(&admin);
        assert_eq!(
            verify_preopened_administrative_child_identity(
                &anchor,
                &open(&normal),
                "ordinary-parent"
            ),
            Ok(()),
            "an ordinary direct child must remain admissible"
        );
        let made = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&alias)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            made.status.success(),
            "real NTFS junction setup failed: {made:?}"
        );
        let alias_target = open(&alias);
        assert_eq!(
            verify_preopened_named_child_identity(&anchor, &alias_target, "alias-parent"),
            Err(IdentityDenied),
            "mounted-root admission must not follow an ordinary NTFS directory junction"
        );
        // A caller can also hand us a handle opened to the reparse entry
        // itself rather than to its target. Both identities must deny.
        const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let link_itself = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT)
            .open(&alias)
            .unwrap();
        let (_, link_attrs, _) = from_handle(&link_itself).unwrap();
        assert_ne!(
            link_attrs & FILE_ATTRIBUTE_REPARSE_POINT,
            0,
            "the negative control must hold an actual junction entry"
        );
        assert_eq!(
            verify_preopened_administrative_child_identity(&anchor, &link_itself, "alias-parent"),
            Err(IdentityDenied),
            "the junction's own kernel object must not impersonate an ordinary directory"
        );
        assert_eq!(
            verify_preopened_administrative_child_identity(&anchor, &alias_target, "alias-parent"),
            Err(IdentityDenied),
            "administrator-controlled parent traversal must never admit a junction"
        );
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"OUTSIDE_BYTES_NEVER_CHANGED"
        );
    }

    #[test]
    fn administrative_chain_denies_intermediate_junction_even_when_final_entry_matches() {
        use std::{os::windows::fs::OpenOptionsExt, process::Command};
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let admin = fixture.path().join("admin");
        let normal = admin.join("ordinary");
        let outside_parent = fixture.path().join("exterior-parent");
        let alias = admin.join("aliased");
        std::fs::create_dir(&admin).unwrap();
        std::fs::create_dir(&normal).unwrap();
        std::fs::create_dir(normal.join("child")).unwrap();
        std::fs::create_dir(&outside_parent).unwrap();
        std::fs::create_dir(outside_parent.join("child")).unwrap();
        std::fs::write(
            outside_parent.join("sentinel.bin"),
            b"EXTERIOR_PARENT_UNCHANGED",
        )
        .unwrap();
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let anchor_parent = open(fixture.path());
        let anchor = open(&admin);
        assert_eq!(
            verify_preopened_administrative_chain(&anchor, &[]),
            Err(IdentityDenied),
            "an empty witness is not evidence of an administrative chain"
        );
        assert!(
            ObservedWindowsAdministrativeChain::observe(&anchor, &[]).is_err(),
            "the revocable observer must also reject an empty witness"
        );
        let normal_parent = open(&normal);
        let normal_child = open(&normal.join("child"));
        assert_eq!(
            verify_preopened_administrative_chain(
                &anchor,
                &[(&normal_parent, "ordinary"), (&normal_child, "child")]
            ),
            Ok(()),
            "a fully ordinary two-component chain must be admitted"
        );
        let mut observed = ObservedWindowsAdministrativeChain::observe(
            &anchor,
            &[(&normal_parent, "ordinary"), (&normal_child, "child")],
        )
        .expect("an independently pinned ordinary chain must admit a non-issuing observation");
        assert_eq!(observed.revalidate(), Ok(()));
        let linked = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&alias)
            .arg(&outside_parent)
            .output()
            .unwrap();
        assert!(
            linked.status.success(),
            "real junction creation failed: {linked:?}"
        );
        let redirected_parent = open(&alias);
        let redirected_child = open(&alias.join("child"));
        assert_eq!(
            verify_preopened_administrative_child_identity(
                &redirected_parent,
                &redirected_child,
                "child"
            ),
            Ok(()),
            "the final legitimate directory cannot attest its parent's administrative origin"
        );
        assert_eq!(
            verify_preopened_administrative_chain(
                &anchor,
                &[
                    (&redirected_parent, "aliased"),
                    (&redirected_child, "child")
                ]
            ),
            Err(IdentityDenied),
            "the independent administrative anchor must reject the intermediate junction"
        );
        assert!(
            ObservedWindowsAdministrativeChain::observe(
                &anchor,
                &[
                    (&redirected_parent, "aliased"),
                    (&redirected_child, "child")
                ]
            )
            .is_err(),
            "the revocable observer must not admit an intermediate exterior junction"
        );
        let mut isolated_only = ObservedWindowsIsolatedRoot::from_preopened_kernel_fixture(
            &redirected_parent,
            open(&alias.join("child")),
            "child",
        )
        .expect("a standalone root fixture follows the valid final edge after the junction");
        assert_eq!(
            isolated_only.revalidate_kernel_binding_only_for_test(),
            Ok(())
        );
        assert!(
            ObservedWindowsChainBoundIsolatedRoot::from_preopened_kernel_fixture(
                &anchor_parent,
                "admin",
                &anchor,
                &[(&redirected_parent, "aliased")],
                open(&alias.join("child")),
                "child",
            )
            .is_err(),
            "the composite must deny the intermediate exterior junction even when root binding passes"
        );
        assert_eq!(
            std::fs::read(outside_parent.join("sentinel.bin")).unwrap(),
            b"EXTERIOR_PARENT_UNCHANGED"
        );
    }

    #[test]
    fn restored_administrative_entry_cannot_revive_revoked_chain_observation() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const SHARE_READ_WRITE_DELETE: u32 = 0x0000_0007;
        let fixture = tempfile::tempdir().unwrap();
        let admin = fixture.path().join("admin");
        let parent_path = admin.join("parent");
        let child_path = parent_path.join("child");
        let retired_path = parent_path.join("retired-child");
        std::fs::create_dir_all(&child_path).unwrap();
        let sentinel = child_path.join("canary.bin");
        std::fs::write(&sentinel, b"REVOCATION_SENTINEL_UNCHANGED").unwrap();
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(SHARE_READ_WRITE_DELETE)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let anchor = open(&admin);
        let parent = open(&parent_path);
        let child = open(&child_path);
        let chain = [(&parent, "parent"), (&child, "child")];
        let mut observation = ObservedWindowsAdministrativeChain::observe(&anchor, &chain)
            .expect("two ordinary NTFS entries must admit a non-issuing observation");
        assert_eq!(observation.revalidate(), Ok(()));
        std::fs::rename(&child_path, &retired_path)
            .expect("the actual NTFS child entry must be movable while handles stay pinned");
        assert_eq!(
            observation.revalidate(),
            Err(IdentityDenied),
            "a missing pinned child must irrevocably revoke the observation"
        );
        std::fs::rename(&retired_path, &child_path).unwrap();
        assert_eq!(
            verify_preopened_administrative_chain(&anchor, &chain),
            Ok(()),
            "negative control: a stateless check forgets that a prior check failed"
        );
        assert_eq!(
            observation.revalidate(),
            Err(IdentityDenied),
            "restored entries must not resurrect the previously revoked observation"
        );
        let mut fresh = ObservedWindowsAdministrativeChain::observe(&anchor, &chain)
            .expect("a separately created non-issuing observation may check the restored chain");
        assert_eq!(fresh.revalidate(), Ok(()));
        assert_eq!(observation.revalidate(), Err(IdentityDenied));
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"REVOCATION_SENTINEL_UNCHANGED"
        );
    }

    #[test]
    fn chain_bound_root_observation_rejects_unrelated_parent_without_mutation() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let authorized = fixture.path().join("authorized");
        let parent_path = authorized.join("parent");
        let legitimate_root = parent_path.join("isolated");
        let outside_parent = fixture.path().join("outside-parent");
        let outside_root = outside_parent.join("isolated");
        std::fs::create_dir_all(&legitimate_root).unwrap();
        std::fs::create_dir_all(&outside_root).unwrap();
        std::fs::write(outside_root.join("canary.bin"), b"OUTSIDE_BYTES_UNCHANGED").unwrap();
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let anchor_parent = open(fixture.path());
        let anchor = open(&authorized);
        let parent = open(&parent_path);
        let exterior_parent = open(&outside_parent);
        let exterior_root = open(&outside_root);
        assert_eq!(
            verify_preopened_administrative_chain(&anchor, &[(&parent, "parent")]),
            Ok(()),
            "the configured administrative ancestry must be an ordinary real NTFS chain"
        );
        assert_eq!(
            verify_preopened_named_child_identity(&parent, &exterior_root, "isolated"),
            Err(IdentityDenied),
            "the exterior root is not a child of the supplied administrative chain"
        );
        let mut root_only = ObservedWindowsIsolatedRoot::from_preopened_kernel_fixture(
            &exterior_parent,
            exterior_root,
            "isolated",
        )
        .unwrap();
        assert_eq!(
            root_only.revalidate_kernel_binding_only_for_test(),
            Ok(()),
            "negative control: the root-only check still accepts its unrelated exterior parent"
        );
        assert!(
            ObservedWindowsChainBoundIsolatedRoot::from_preopened_kernel_fixture(
                &anchor_parent,
                "authorized",
                &anchor,
                &[(&parent, "parent")],
                open(&outside_root),
                "isolated"
            )
            .is_err(),
            "the chain-bound root must not admit a directory outside the supplied anchor"
        );
        let mut inside = ObservedWindowsChainBoundIsolatedRoot::from_preopened_kernel_fixture(
            &anchor_parent,
            "authorized",
            &anchor,
            &[(&parent, "parent")],
            open(&legitimate_root),
            "isolated",
        )
        .expect("ordinary positive control must bind its exact administrative parent");
        assert_eq!(inside.revalidate_kernel_only_for_test(), Ok(()));
        assert!(
            observe_preopened_chain_bound_isolated_service_root(
                &anchor_parent,
                "authorized",
                &anchor,
                &[(&parent, "parent")],
                open(&legitimate_root),
                "isolated"
            )
            .is_err(),
            "normal interactive users cannot attest the real restricted SCM identity"
        );
        assert_eq!(
            std::fs::read(outside_root.join("canary.bin")).unwrap(),
            b"OUTSIDE_BYTES_UNCHANGED"
        );
    }

    #[test]
    fn composite_denies_foreign_administrative_anchor_despite_valid_internal_chain() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let configured_anchor = fixture.path().join("configured-stage");
        let foreign_anchor = fixture.path().join("foreign-stage");
        let configured_root = configured_anchor.join("mount-parent").join("isolated");
        let foreign_parent = foreign_anchor.join("mount-parent");
        let foreign_root = foreign_parent.join("isolated");
        std::fs::create_dir_all(&configured_root).unwrap();
        std::fs::create_dir_all(&foreign_root).unwrap();
        let canary = foreign_root.join("outside-canary");
        std::fs::write(&canary, b"FOREIGN_ANCHOR_BYTES_UNCHANGED").unwrap();
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let configured_parent = open(fixture.path());
        let configured_anchor_handle = open(&configured_anchor);
        let configured_stage_parent = open(&configured_anchor.join("mount-parent"));
        let mut admitted = ObservedWindowsChainBoundIsolatedRoot::from_preopened_kernel_fixture(
            &configured_parent,
            "configured-stage",
            &configured_anchor_handle,
            &[(&configured_stage_parent, "mount-parent")],
            open(&configured_root),
            "isolated",
        )
        .expect("configured NTFS source must remain an admissible non-issuing observation");
        assert_eq!(admitted.revalidate_kernel_only_for_test(), Ok(()));

        let forged_anchor = open(&foreign_anchor);
        let forged_parent = open(&foreign_parent);
        assert_eq!(
            verify_preopened_administrative_chain(
                &forged_anchor,
                &[(&forged_parent, "mount-parent")],
            ),
            Ok(()),
            "negative control: unrelated NTFS anchor has a valid internal chain"
        );
        assert_eq!(
            verify_preopened_administrative_child_identity(
                &configured_parent,
                &forged_anchor,
                "configured-stage",
            ),
            Err(IdentityDenied),
            "configured source parent and named child distinguish a foreign anchor"
        );
        assert!(
            ObservedWindowsChainBoundIsolatedRoot::from_preopened_kernel_fixture(
                &configured_parent,
                "configured-stage",
                &forged_anchor,
                &[(&forged_parent, "mount-parent")],
                open(&foreign_root),
                "isolated",
            )
            .is_err(),
            "complete foreign chain must not substitute for the configured source anchor"
        );
        assert_eq!(
            std::fs::read(&canary).unwrap(),
            b"FOREIGN_ANCHOR_BYTES_UNCHANGED"
        );
    }

    // NEGATIVE SECURITY EVIDENCE: the current non-issuing fixture authenticates
    // parent/child identity, not the provisioned origin of the parent itself.
    // Passing this test means the missing origin-authority gate is observable;
    // it does NOT mean an untrusted caller is authorized to select a root.
    #[test]
    fn negative_control_caller_selected_anchor_parent_is_not_authenticated_origin() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let fixture = tempfile::tempdir().unwrap();
        let provisioned_parent_path = fixture.path().join("provisioned-parent");
        let substituted_parent_path = fixture.path().join("substituted-parent");
        let provisioned_root = provisioned_parent_path
            .join("stage")
            .join("mount-parent")
            .join("isolated");
        let substituted_anchor = substituted_parent_path.join("stage");
        let substituted_chain_parent = substituted_anchor.join("mount-parent");
        let substituted_root = substituted_chain_parent.join("isolated");
        std::fs::create_dir_all(&provisioned_root).unwrap();
        std::fs::create_dir_all(&substituted_root).unwrap();
        let outside_canary = substituted_root.join("canary.bin");
        let outside_bytes = b"UNTRUSTED_PARENT_ORIGIN_BYTES_UNCHANGED";
        std::fs::write(&outside_canary, outside_bytes).unwrap();
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let provisioned_parent = open(&provisioned_parent_path);
        let substituted_parent = open(&substituted_parent_path);
        assert_eq!(
            crate::windows_program_data_origin::verify_system_program_data_parent(
                &substituted_parent,
            ),
            Err(IdentityDenied),
            "the independently known ProgramData parent must reject a chosen tree"
        );
        let anchor = open(&substituted_anchor);
        let chain_parent = open(&substituted_chain_parent);

        // The genuine configured parent correctly rejects a foreign child.
        assert_eq!(
            verify_preopened_administrative_child_identity(&provisioned_parent, &anchor, "stage",),
            Err(IdentityDenied),
        );
        // COUNTEREXAMPLE: the same foreign chain becomes internally consistent
        // when its own parent is supplied. No OS-provisioned policy origin is
        // consulted by this kernel-only observation.
        let mut observed = ObservedWindowsChainBoundIsolatedRoot::from_preopened_kernel_fixture(
            &substituted_parent,
            "stage",
            &anchor,
            &[(&chain_parent, "mount-parent")],
            open(&substituted_root),
            "isolated",
        )
        .expect("a caller-selected source parent is not authenticated policy provenance");
        assert_eq!(observed.revalidate_kernel_only_for_test(), Ok(()));
        assert_eq!(std::fs::read(&outside_canary).unwrap(), outside_bytes);
        // No native I/O grant or production service is created by this test.
    }

    // Non-release NTFS kernel constraint, NOT a sticky-revocation proof:
    // ordinary ancestor rename cannot exercise a retirement interleaving
    // while real descendant handles stay open, even with FILE_SHARE_DELETE.
    #[test]
    fn pinned_ntfs_descendants_block_source_anchor_rename_nonrelease() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const SHARE_READ_WRITE_DELETE: u32 = 0x0000_0007;
        let fixture = tempfile::tempdir().unwrap();
        let stage = fixture.path().join("admin-stage");
        let retired = fixture.path().join("retired-admin-stage");
        let parent_path = stage.join("mount-parent");
        let root_path = parent_path.join("isolated");
        std::fs::create_dir_all(&root_path).unwrap();
        let canary = root_path.join("canary.bin");
        let original = b"RETIRED_SOURCE_ANCHOR_BYTES_UNCHANGED";
        std::fs::write(&canary, original).unwrap();

        // Explicit delete sharing distinguishes descendant handle custody
        // from a missing FILE_SHARE_DELETE flag.
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(SHARE_READ_WRITE_DELETE)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let source_parent = open(fixture.path());
        let anchor = open(&stage);
        let parent = open(&parent_path);
        let mut original_observation =
            ObservedWindowsChainBoundIsolatedRoot::from_preopened_kernel_fixture(
                &source_parent,
                "admin-stage",
                &anchor,
                &[(&parent, "mount-parent")],
                open(&root_path),
                "isolated",
            )
            .expect("positive control: original pinned NTFS chain must be internally valid");
        assert_eq!(
            original_observation.revalidate_kernel_only_for_test(),
            Ok(())
        );

        let blocked = std::fs::rename(&stage, &retired)
            .expect_err("real pinned descendants must block ordinary ancestor rename");
        assert_eq!(
            blocked.kind(),
            std::io::ErrorKind::PermissionDenied,
            "NTFS returned a different failure; this kernel constraint is not established"
        );
        assert!(stage.is_dir());
        assert!(!retired.exists());
        assert_eq!(
            original_observation.revalidate_kernel_only_for_test(),
            Ok(()),
            "no namespace transition occurred; the valid observation must remain valid"
        );
        assert_eq!(std::fs::read(&canary).unwrap(), original);

        // The actual same-directory move MUST succeed once every pinned
        // descendant has been closed; otherwise the setup is inconclusive.
        drop(original_observation);
        drop(parent);
        drop(anchor);
        drop(source_parent);
        std::fs::rename(&stage, &retired)
            .expect("without pinned handles the same NTFS rename must succeed");
        assert!(!stage.exists());
        assert!(retired.is_dir());
        std::fs::rename(&retired, &stage).unwrap();
        assert_eq!(std::fs::read(&canary).unwrap(), original);
        // This does not test revocation under a successfully installed swap.
        // Invariant O and production source-root custody remain unproven.
    }

    #[test]
    fn kernel_only_binding_stays_valid_after_parent_junction_removal_nonrelease() {
        use std::{os::windows::fs::OpenOptionsExt, process::Command};
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const SHARE_READ_WRITE_DELETE: u32 = 0x0000_0007;
        let fixture = tempfile::tempdir().unwrap();
        let authorized = fixture.path().join("authorized");
        let exterior_parent = fixture.path().join("exterior-parent");
        let junction = authorized.join("parent");
        let root_path = exterior_parent.join("isolated");
        std::fs::create_dir(&authorized).unwrap();
        std::fs::create_dir_all(&root_path).unwrap();
        let original = b"ROOT_CUSTODY_SENTINEL_UNCHANGED";
        std::fs::write(root_path.join("canary.bin"), original).unwrap();
        let linked = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&exterior_parent)
            .output()
            .unwrap();
        assert!(
            linked.status.success(),
            "real junction setup failed: {linked:?}"
        );
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(SHARE_READ_WRITE_DELETE)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let administrative_ancestor = open(&authorized);
        let parent = open(&junction);
        let root = open(&junction.join("isolated"));
        assert_eq!(
            verify_preopened_named_child_identity(&administrative_ancestor, &parent, "parent"),
            Err(IdentityDenied),
            "the newly enforced root-mount check denies the live directory junction"
        );
        let mut observation =
            ObservedWindowsIsolatedRoot::from_preopened_kernel_fixture(&parent, root, "isolated")
                .expect("opened parent/child objects really match before the namespace change");
        assert_eq!(
            observation.revalidate_kernel_binding_only_for_test(),
            Ok(())
        );
        std::fs::remove_dir(&junction)
            .expect("the actual junction entry must disappear without deleting its target");
        assert!(!junction.exists(), "the authorized pathname must disappear");
        assert!(root_path.is_dir());
        assert_eq!(
            verify_preopened_named_child_identity(&administrative_ancestor, &parent, "parent"),
            Err(IdentityDenied),
            "an independent pinned ancestor must detect the removed parent entry"
        );
        // NEGATIVE SECURITY EVIDENCE, never an acceptance of authorization:
        // the two still-open handles preserve parent/child identity after
        // removal of the *only configured* authorized namespace entry.
        // Full administrative ancestry and origin custody are NOT checked.
        let pinned_identity = from_handle(&observation.root.file).unwrap();
        assert_eq!(
            pinned_identity,
            from_handle(&open(&root_path)).unwrap(),
            "the exterior name must resolve to the same kernel file object"
        );
        assert_eq!(
            observation.revalidate_kernel_binding_only_for_test(),
            Ok(()),
            "COUNTEREXAMPLE: handle-relative child identity alone cannot detect removed parent junctions"
        );
        assert_eq!(
            std::fs::read(root_path.join("canary.bin")).unwrap(),
            original
        );
    }

    #[test]
    fn revoked_windows_observation_rejects_real_junction_replacement_and_new_observation_recovers()
    {
        use std::{os::windows::fs::OpenOptionsExt, process::Command};
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let f = tempfile::tempdir().unwrap();
        let original = f.path().join("isolated");
        let retired = f.path().join("retired-original");
        let exterior = f.path().join("external");
        std::fs::create_dir(&original).unwrap();
        std::fs::create_dir(&exterior).unwrap();
        let sentinel = exterior.join("exterior.bin");
        std::fs::write(&sentinel, b"EXTERIOR_JUNCTION_BYTES_UNCHANGED").unwrap();
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let parent = open(f.path());
        let mut old = ObservedWindowsIsolatedRoot::from_preopened_kernel_fixture(
            &parent,
            open(&original),
            "isolated",
        )
        .unwrap();
        assert_eq!(old.revalidate_kernel_binding_only_for_test(), Ok(()));
        std::fs::rename(&original, &retired).unwrap();
        let made = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&original)
            .arg(&exterior)
            .output()
            .unwrap();
        assert!(
            made.status.success(),
            "real NTFS junction creation failed: {made:?}"
        );
        assert_eq!(
            old.revalidate_kernel_binding_only_for_test(),
            Err(IdentityDenied),
            "an unrelated NTFS junction target must revoke the stale observation"
        );
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"EXTERIOR_JUNCTION_BYTES_UNCHANGED"
        );
        std::fs::remove_dir(&original).expect("delete only the NTFS junction itself");
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"EXTERIOR_JUNCTION_BYTES_UNCHANGED"
        );
        std::fs::rename(&retired, &original).unwrap();
        assert_eq!(
            old.revalidate_kernel_binding_only_for_test(),
            Err(IdentityDenied),
            "restoring the original root must never reactivate an old observation"
        );
        let mut newly_issued = ObservedWindowsIsolatedRoot::from_preopened_kernel_fixture(
            &parent,
            open(&original),
            "isolated",
        )
        .unwrap();
        assert_eq!(
            newly_issued.revalidate_kernel_binding_only_for_test(),
            Ok(())
        );
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"EXTERIOR_JUNCTION_BYTES_UNCHANGED"
        );
    }

    #[test]
    fn isolated_root_observation_requires_verified_scm_token_acl_and_volume() {
        use std::os::windows::fs::OpenOptionsExt;
        const BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let f = tempfile::tempdir().unwrap();
        let child = f.path().join("separate-root");
        std::fs::create_dir(&child).unwrap();
        let open_dir = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(BACKUP_SEMANTICS)
                .open(path)
                .unwrap()
        };
        let parent = open_dir(f.path());
        let root = open_dir(&child);
        // Contract: there is no path-only, caller-supplied DACL, or
        // free-standing volume-serial constructor for this observer.
        let _typecheck: fn(
            &File,
            File,
            &str,
        ) -> Result<ObservedWindowsIsolatedRoot, IdentityDenied> =
            observe_preopened_isolated_service_root;
        assert_eq!(
            observe_preopened_isolated_service_root(&parent, root, "separate-root").err(),
            Some(IdentityDenied),
            "a normal interactive user cannot mint an SCM-bound root observation"
        );
    }

    #[test]
    fn staging_bootstrap_requires_an_observed_scoped_service_handle() {
        use crate::handle_mkdir::ProtectedStagingDirectory;
        // Compile-time contract: no strings, ambient paths, or naked Dir
        // can be passed to the constructor for protected staging.
        let checked: fn(ObservedWindowsStateDirectory) -> ProtectedStagingDirectory =
            ProtectedStagingDirectory::from_verified_windows_state;
        let _ = checked;
    }

    #[test]
    fn unprovisioned_process_never_issues_a_policy_state_observation() {
        let temp = tempfile::tempdir().unwrap();
        let open_directory = || {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
                .open(temp.path())
                .unwrap()
        };
        assert!(
            crate::handle_mkdir::ProtectedStagingDirectory::from_preopened_service_state(
                open_directory()
            )
            .is_err(),
            "ordinary Windows process must not convert arbitrary handle to protected staging"
        );
        assert_eq!(
            observe_preopened_service_state({
                use std::os::windows::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS,
                    )
                    .open(temp.path())
                    .unwrap()
            })
            .err(),
            Some(IdentityDenied),
        );
    }
}
