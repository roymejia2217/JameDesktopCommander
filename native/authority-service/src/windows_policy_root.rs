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
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        AclSizeInformation,
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        EqualSid, GetAclInformation, GetSecurityDescriptorControl, IsValidAcl, IsWellKnownSid,
        WinBuiltinAdministratorsSid, WinLocalSystemSid, ACL, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    },
    Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT,
    },
};

const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const REQUIRED_ACE_FLAGS: u8 = 0x03; // OI + CI: children and SQLite files must inherit.
const REQUIRED_ADMIN_RIGHTS: u32 = 0x001f_01ff; // Win32 FILE_ALL_ACCESS.
const REQUIRED_SERVICE_RIGHTS: u32 = 0x0003_01bf; // Documented NTFS Modify baseline.

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

fn validate_ace_set(aces: &[AceSummary]) -> Result<(), IdentityDenied> {
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
            Principal::Service
                if !service
                    && ace.mask & REQUIRED_SERVICE_RIGHTS == REQUIRED_SERVICE_RIGHTS
                    && ace.mask & (WRITE_DAC | WRITE_OWNER | GENERIC_ALL) == 0 =>
            {
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

fn inspect_acl(file: &File, service_sid: &[u8]) -> Result<(), IdentityDenied> {
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
    validate_ace_set(&summaries)
}

/// OS-handle volume isolation preflight. A volume serial number is only a
/// necessary discriminator, NOT a trustworthy volume GUID or unique physical
/// storage-origin proof; two independently formatted volumes can collide.
/// The actual Windows root issuer remains disabled pending OS-principal ACL
/// attestation, protected component traversal, filesystem identity and review.
#[derive(Debug, Clone, Copy)]
struct WindowsVolumeBoundary {
    parent_serial: Option<u32>,
    root_serial: Option<u32>,
    parent_attributes: u32,
    root_attributes: u32,
    parent_file_index: Option<u64>,
    root_file_index: Option<u64>,
}

fn validate_volume_boundary(observed: WindowsVolumeBoundary) -> Result<(), IdentityDenied> {
    let (Some(parent_volume), Some(root_volume)) = (observed.parent_serial, observed.root_serial)
    else {
        return Err(IdentityDenied);
    };
    if parent_volume == 0
        || root_volume == 0
        || parent_volume == root_volume
        || observed.parent_file_index.is_none_or(|id| id == 0)
        || observed.root_file_index.is_none_or(|id| id == 0)
        || observed.parent_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || observed.root_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || observed.parent_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || observed.root_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(IdentityDenied);
    }
    Ok(())
}

/// Read metadata from the two already-open kernel objects, never ambient
/// paths or client-provided serials. Does NOT establish actual parent/child
/// relationship, owner/ACL, filesystem identity or authorization; a caller
/// must independently prove those stronger properties before any grant.
pub fn verify_preopened_volume_separation(
    parent: &File,
    root: &File,
) -> Result<(), IdentityDenied> {
    fn from_handle(opened: &File) -> Result<(u32, u32, u64), IdentityDenied> {
        // SAFETY: the initialized Win32 POD buffer is exclusively borrowed
        // by GetFileInformationByHandle for the lifetime of this owned File.
        // No pointer escapes; unsuccessful kernel queries fail closed.
        let mut result: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
        if unsafe { GetFileInformationByHandle(opened.as_raw_handle().cast(), &mut result) } == 0 {
            return Err(IdentityDenied);
        }
        let index = (u64::from(result.nFileIndexHigh) << 32) | u64::from(result.nFileIndexLow);
        Ok((result.dwVolumeSerialNumber, result.dwFileAttributes, index))
    }
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

/// Data-only observer. It requires the current *kernel* process token to be
/// the dedicated SCM service identity before looking at any supplied handle.
/// Its caller must independently acquire the state directory via protected,
/// component-pinned bootstrap. This function cannot perform that bootstrap.
pub fn observe_preopened_service_state(
    file: File,
) -> Result<ObservedWindowsStateDirectory, IdentityDenied> {
    verify_service_identity()?;
    let attrs = file.metadata().map_err(|_| IdentityDenied)?;
    if !attrs.is_dir() || attrs.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(IdentityDenied);
    }
    let service_sid = crate::windows_token::service_sid_bytes().map_err(|_| IdentityDenied)?;
    inspect_acl(&file, &service_sid)?;
    Ok(ObservedWindowsStateDirectory { file })
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn distinct_volume_admission_denies_unavailable_equal_or_untrusted_metadata() {
        let valid = WindowsVolumeBoundary {
            parent_serial: Some(0x1234),
            root_serial: Some(0x5678),
            parent_attributes: 0x10,
            root_attributes: 0x10,
            parent_file_index: Some(4),
            root_file_index: Some(9),
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
                root_file_index: Some(0),
                ..valid
            },
            WindowsVolumeBoundary {
                parent_file_index: Some(0),
                ..valid
            },
        ] {
            assert_eq!(validate_volume_boundary(rejected), Err(IdentityDenied));
        }
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
