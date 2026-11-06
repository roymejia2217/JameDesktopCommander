#[cfg(windows)]
mod windows {
    use std::{fs, path::Path, process::Command};
    use tunnel_operator_authority::{
        observe_private_file_custody, FileCustodyDenied, FileCustodyEvidence,
    };

    fn fixture() -> tempfile::TempDir {
        tempfile::tempdir().expect("isolated disposable Windows fixture")
    }

    fn current_sid_string() -> String {
        let sid = tunnel_operator_authority::observe_current_process_user_sid()
            .expect("Windows process TokenUser");
        let authority = sid[2..8].iter().fold(0u64, |n, &b| (n << 8) | u64::from(b));
        let mut text = format!("S-{}-{authority}", sid[0]);
        for index in 0..usize::from(sid[1]) {
            let start = 8 + 4 * index;
            let sub = u32::from_le_bytes(sid[start..start + 4].try_into().unwrap());
            text.push_str(&format!("-{sub}"));
        }
        text
    }

    fn protected_fixture(root: &Path) {
        // Create a private synthetic DACL; inherited TEMP sandbox readers
        // must not be silently interpreted as safe for credential storage.
        let grant = format!("*{}:(OI)(CI)(F)", current_sid_string());
        for args in [vec!["/grant:r", &grant], vec!["/inheritance:r"]] {
            let result = Command::new("icacls.exe")
                .arg(root)
                .args(args)
                .output()
                .expect("native private ACL fixture setup");
            assert!(
                result.status.success(),
                "must prove private DACL was installed"
            );
        }
        fs::create_dir(root.join("private")).expect("private dir");
        fs::write(
            root.join("private").join("key.txt"),
            b"fixture-not-a-secret",
        )
        .expect("fixture file");
    }

    #[test]
    fn ordinary_private_fixture_is_observed_without_authorization() {
        let root = fixture();
        protected_fixture(root.path());
        assert_eq!(
            observe_private_file_custody(root.path(), Path::new("private/key.txt")),
            Ok(FileCustodyEvidence::ObservedOnly)
        );
        assert_eq!(
            fs::read(root.path().join("private/key.txt")).expect("fixture bytes"),
            b"fixture-not-a-secret"
        );
    }
    #[test]
    fn hardlink_to_outside_object_is_denied_without_modifying_bytes() {
        let root = fixture();
        protected_fixture(root.path());
        let outside = fixture();
        let alias = outside.path().join("external.txt");
        let original = root.path().join("private/key.txt");
        fs::hard_link(&original, &alias).expect("hardlink adversarial setup must succeed");
        let sentinel_before = fs::read(&alias).expect("read sentinel");
        assert_eq!(
            observe_private_file_custody(root.path(), Path::new("private/key.txt")),
            Err(FileCustodyDenied::Unverifiable)
        );
        assert_eq!(fs::read(&alias).expect("read sentinel"), sentinel_before);
    }

    #[test]
    fn missing_file_and_escape_are_denied() {
        let root = fixture();
        protected_fixture(root.path());
        for value in [
            "private/absent.txt",
            "../external.txt",
            "private/../key.txt",
        ] {
            assert_eq!(
                observe_private_file_custody(root.path(), Path::new(value)),
                Err(FileCustodyDenied::Unverifiable)
            );
        }
    }
    #[test]
    fn broad_world_modify_ace_is_denied() {
        let root = fixture();
        protected_fixture(root.path());
        let file = root.path().join("private/key.txt");
        // Use the official Windows ACL tool on a synthetic disposable file.
        let status = Command::new("icacls.exe")
            .arg(&file)
            .args(["/grant", "*S-1-1-0:(M)"])
            .output()
            .expect("invoke Windows native ACL fixture setup");
        assert!(
            status.status.success(),
            "must prove hostile DACL was installed"
        );
        assert_eq!(
            observe_private_file_custody(root.path(), Path::new("private/key.txt")),
            Err(FileCustodyDenied::Unverifiable)
        );
    }

    #[test]
    fn broad_world_read_ace_is_denied_for_credential_privacy() {
        let root = fixture();
        protected_fixture(root.path());
        let file = root.path().join("private/key.txt");
        let status = Command::new("icacls.exe")
            .arg(&file)
            .args(["/grant", "*S-1-1-0:(R)"])
            .output()
            .expect("native world-read ACL setup");
        assert!(status.status.success(), "read ACE attack setup must work");
        assert_eq!(
            observe_private_file_custody(root.path(), Path::new("private/key.txt")),
            Err(FileCustodyDenied::Unverifiable)
        );
    }

    #[test]
    fn broad_parent_ace_is_denied_even_if_file_remains_private() {
        let root = fixture();
        protected_fixture(root.path());
        let parent = root.path().join("private");
        let status = Command::new("icacls.exe")
            .arg(&parent)
            .args(["/grant", "*S-1-1-0:(M)"])
            .output()
            .expect("native parent ACL setup");
        assert!(status.status.success(), "parent ACL attack setup must work");
        assert_eq!(
            observe_private_file_custody(root.path(), Path::new("private/key.txt")),
            Err(FileCustodyDenied::Unverifiable)
        );
    }

    #[test]
    fn junction_ancestor_is_denied() {
        let root = fixture();
        protected_fixture(root.path());
        let junction = root.path().join("junction");
        let target = root.path().join("private");
        let status = Command::new("cmd.exe")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .expect("junction creation fixture command");
        assert!(status.status.success(), "junction attack setup must work");
        assert_eq!(
            observe_private_file_custody(root.path(), Path::new("junction/key.txt")),
            Err(FileCustodyDenied::Unverifiable)
        );
    }
}
