//! Admission regressions; ordinary local directories are not volumes.
use super::*;

#[test]
fn volume_guid_syntax_rejects_subpaths_and_device_names() {
    let root = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\";
    assert!(valid_guid_root(root));
    for invalid in [
        r"C:\",
        r"\\.\C:",
        r"\\?\Volume{bad}\",
        &format!("{root}nested"),
        &root[..root.len() - 1],
    ] {
        assert!(!valid_guid_root(invalid), "{invalid}");
    }
}

#[test]
fn ordinary_directory_handle_is_not_volume_root() {
    let file = open_directory(&std::env::temp_dir()).unwrap();
    let observed = final_guid_path(&file).unwrap();
    assert!(!valid_guid_root(&observed), "{observed}");
    assert!(volume_identity(&file).is_err());
}

#[test]
fn acl_contract_refuses_extra_trustees_and_excess_service_rights() {
    let service = vec![1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0];
    let admin = sid_bytes("S-1-5-32-544").unwrap();
    let system = sid_bytes("S-1-5-18").unwrap();
    let expected = vec![
        Ace {
            sid: admin.clone(),
            mask: FULL,
            flags: 3,
        },
        Ace {
            sid: system,
            mask: FULL,
            flags: 3,
        },
        Ace {
            sid: service.clone(),
            mask: MODIFY,
            flags: 3,
        },
    ];
    assert!(check_root_aces(&expected, &service).is_ok());
    let mut broad = expected.clone();
    broad[2].mask = FULL;
    assert!(check_root_aces(&broad, &service).is_err());
    let mut broad = expected.clone();
    broad.push(Ace {
        sid: sid_bytes("S-1-1-0").unwrap(),
        mask: MODIFY,
        flags: 3,
    });
    assert!(check_root_aces(&broad, &service).is_err());
    let mut wrong = expected.clone();
    wrong[0].flags = 0;
    assert!(check_root_aces(&wrong, &service).is_err());
}

#[test]
fn actual_ntfs_descriptor_accepts_exact_acl_and_rejects_extra_ace() {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        SetFileSecurityW, PROTECTED_DACL_SECURITY_INFORMATION,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    let root = std::env::temp_dir().join(format!(
        "jdc-volume-acl-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    let service = observe_process_sid().unwrap();
    let mut sid_text = ptr::null_mut();
    assert_ne!(
        unsafe { ConvertSidToStringSidW(service.as_ptr().cast_mut().cast(), &mut sid_text) },
        0
    );
    let _sid_text = Local(sid_text.cast());
    let len = (0..192)
        .find(|&i| unsafe { *sid_text.add(i) == 0 })
        .unwrap();
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, len) }).unwrap();
    let apply = |target: &Path, extra: &str| {
        let path: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(target.as_os_str())
            .chain(Some(0))
            .collect();
        let sddl = format!(
            "D:P(A;OICI;0x1f01ff;;;BA)(A;OICI;0x1f01ff;;;SY)(A;OICI;0x1301bf;;;{text}){extra}"
        );
        let mut descriptor = ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(&sddl).as_ptr(),
                    1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0
        );
        let _descriptor = Local(descriptor);
        assert_ne!(
            unsafe {
                SetFileSecurityW(
                    path.as_ptr(),
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    descriptor,
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
    };
    apply(&root, "");
    let held = open_directory(&root).unwrap();
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                held.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        },
        0
    );
    let _descriptor = Local(descriptor);
    let owner = copy_sid(owner).unwrap();
    security(&held, &service, &owner, true, true).unwrap();
    let child = root.join(".jdc-state");
    fs::create_dir(&child).unwrap();
    let file = child.join("policy.sqlite3");
    fs::write(&file, b"fixture").unwrap();
    security(
        &open_directory(&child).unwrap(),
        &service,
        &owner,
        false,
        true,
    )
    .unwrap();
    security(&File::open(&file).unwrap(), &service, &owner, false, false).unwrap();
    let sidecar = child.join("policy.sqlite3-journal");
    fs::write(&sidecar, b"journal fixture").unwrap();
    security(
        &File::open(&sidecar).unwrap(),
        &service,
        &owner,
        false,
        false,
    )
    .unwrap();
    // Keep inheritance enabled, and verify that the actual descriptor
    // contains an additional explicit ACE before asking the admission check.
    // A protected-DACL rejection alone would not test the ACE contract.
    let extra_unprotected = |target: &Path, directory: bool| {
        let flags = if directory { "OICIID" } else { "ID" };
        let sddl = format!("D:AI(A;;0x120089;;;WD)(A;{flags};0x1f01ff;;;BA)(A;{flags};0x1f01ff;;;SY)(A;{flags};0x1301bf;;;{text})");
        let mut descriptor = ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(&sddl).as_ptr(),
                    1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0
        );
        let _descriptor = Local(descriptor);
        let path: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(target.as_os_str())
            .chain(Some(0))
            .collect();
        assert_ne!(
            unsafe {
                SetFileSecurityW(
                    path.as_ptr(),
                    DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                    descriptor,
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        let file = if directory {
            open_directory(target).unwrap()
        } else {
            File::open(target).unwrap()
        };
        let mut acl = ptr::null_mut();
        let mut sd = ptr::null_mut();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut acl,
                    ptr::null_mut(),
                    &mut sd,
                )
            },
            0
        );
        let _descriptor = Local(sd);
        let (mut control, mut rev) = (0u16, 0u32);
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut rev) },
            0
        );
        assert_eq!(control & SE_DACL_PROTECTED, 0);
        assert_eq!(unsafe { (*acl).AceCount }, 4);
        let everyone = sid_bytes("S-1-1-0").unwrap();
        let found = (0..4).any(|i| {
            let mut raw = ptr::null_mut();
            assert_ne!(unsafe { GetAce(acl, i, &mut raw) }, 0);
            let a = raw.cast::<ACCESS_ALLOWED_ACE>();
            unsafe {
                (*a).Header.AceType == 0
                    && (*a).Header.AceFlags == 0
                    && (*a).Mask == 0x120089
                    && copy_sid(
                        raw.cast::<u8>()
                            .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                            .cast(),
                    )
                    .unwrap()
                        == everyone
            }
        });
        assert!(found, "expected actual explicit Everyone ACE");
        assert!(security(&file, &service, &owner, false, directory).is_err());
        assert!(security(&held, &service, &owner, true, true).is_ok());
    };
    extra_unprotected(&sidecar, false);
    extra_unprotected(&child, true);
    // Also retain independent protected-DACL negatives.
    apply(&sidecar, "(A;;0x120089;;;WD)");
    assert!(security(
        &File::open(&sidecar).unwrap(),
        &service,
        &owner,
        false,
        false
    )
    .is_err());
    assert!(security(&held, &service, &owner, true, true).is_ok());
    apply(&child, "(A;OICI;0x120089;;;WD)");
    assert!(security(
        &open_directory(&child).unwrap(),
        &service,
        &owner,
        false,
        true
    )
    .is_err());
    assert!(security(&held, &service, &owner, true, true).is_ok());
    apply(&root, "(A;OICI;0x120089;;;WD)");
    assert!(security(&held, &service, &owner, true, true).is_err());
    apply(&root, "");
    assert!(security(&held, &service, &owner, true, true).is_ok());
}
