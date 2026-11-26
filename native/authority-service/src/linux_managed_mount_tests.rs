//! Nonshipping Linux mount topology tests. No runtime grant.
use super::*;
#[test]
fn topology_rejects_bind_aliases_child_mounts_shared_and_subvolume_roots() {
    let base = "10 1 0:40 / /private rw,nosuid,nodev - tmpfs tmpfs rw\n";
    assert!(check_topology(base, 10, 1, (0, 40)).is_ok());
    for invalid in [
        "10 1 0:40 /sub /private rw,nosuid,nodev - tmpfs tmpfs rw\n",
        "10 1 0:40 / /private rw,nosuid,nodev shared:2 - tmpfs tmpfs rw\n",
        "10 1 0:40 / /private rw - tmpfs tmpfs rw\n",
        "10 1 0:40 / /private rw,nosuid,nodev - ext4 /dev/sda rw\n",
        "10 2 0:40 / /private rw,nosuid,nodev - tmpfs tmpfs rw\n",
        "10 1 0:40 / /private rw,nosuid,nodev - tmpfs tmpfs rw\n11 2 0:40 / /alias rw - tmpfs tmpfs rw\n",
        "10 1 0:40 / /private rw,nosuid,nodev - tmpfs tmpfs rw\n11 10 0:41 / /private/child rw - tmpfs tmpfs rw\n",
        "10 1 0:40 / /private rw,nosuid,nodev - tmpfs tmpfs rw\nbad",
    ] {
        assert!(check_topology(invalid,10,1,(0,40)).is_err(),"{invalid}");
    }
}

#[test]
fn ordinary_directory_is_not_a_whole_mount_even_with_private_permissions() {
    let file = File::open(".").unwrap();
    assert!(mount_identity(&file, true).is_err());
    assert!(VerifiedMount::open(&std::env::current_dir().unwrap()).is_err());
    // The kernel must still report the real mount id for ordinary objects.
    let observed = mount_identity(&file, false).unwrap();
    assert_ne!(observed.id, 0);
}
