#!/usr/bin/env bash
# T011 #148: disposable Linux mount/device isolation proof. NON-RELEASE.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_OS:-}" != Linux ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted || "$(id -u)" -eq 0 ]]; then
  echo 'E_STORAGE_DOMAIN_HOSTED_LINUX_REQUIRED' >&2
  exit 1
fi
command -v mountpoint >/dev/null
command -v findmnt >/dev/null
command -v setpriv >/dev/null
getent passwd jdc-authority >/dev/null
getent passwd nobody >/dev/null
sudo -n true
service_uid="$(id -u jdc-authority)"
service_gid="$(id -g jdc-authority)"
attacker_uid="$(id -u nobody)"
[[ "$service_uid" -ne 0 && "$attacker_uid" -ne 0 &&
   "$service_uid" -ne "$attacker_uid" ]] || exit 1
base="$(mktemp -d /tmp/jdc-t011-storage.XXXXXXXX)"
isolated="$base/service-volume"
attacker="$base/attacker-owned"
bind_alias=''
mkdir -- "$isolated" "$attacker"
chmod 0711 "$base"
# The mountpoint's immediate parent belongs to the trusted administrator,
# not to the service or the attacker. Without this, a same-principal process
# could rename the mountpoint despite the isolated volume's own 0700 mode.
sudo -n chown root:root "$base"
sudo -n chown nobody:"$(id -gn nobody)" "$attacker"
sudo -n chmod 0700 "$attacker"
cleanup() {
  local code=$?
  trap - EXIT
  if [[ -n "$bind_alias" ]] && findmnt --kernel --mountpoint "$bind_alias" --noheadings --output TARGET >/dev/null; then
    sudo -n umount -- "$bind_alias" || code=1
  fi
  if mountpoint -q "$isolated"; then
    sudo -n umount -- "$isolated" || code=1
  fi
  if [[ -n "$bind_alias" ]] && findmnt --kernel --mountpoint "$bind_alias" --noheadings --output TARGET >/dev/null; then
    echo 'E_STORAGE_CLEANUP_BIND_MOUNT_ACTIVE' >&2; exit 1
  fi
  if mountpoint -q "$isolated"; then
    echo 'E_STORAGE_CLEANUP_VOLUME_ACTIVE' >&2; exit 1
  fi
  [[ "$base" == /tmp/jdc-t011-storage.* ]] || exit 1
  sudo -n rm -rf -- "$base" || code=1
  exit "$code"
}
trap cleanup EXIT
# The real kernel must supply a separate mount device. Never fake an
# isolated root by putting two directories on the same filesystem.
sudo -n mount -t tmpfs -o "size=8m,mode=0700,uid=$service_uid,gid=$service_gid" tmpfs "$isolated"
mountpoint -q "$isolated"
[[ "$(stat -c %d "$isolated")" != "$(stat -c %d "$attacker")" ]] || {
  echo 'E_STORAGE_DOMAIN_SAME_DEVICE' >&2; exit 1;
}
[[ "$(stat -c %u:%g:%a "$isolated")" == "$service_uid:$service_gid:700" ]] || exit 1
service_file="$isolated/service.bin"
outside_file="$attacker/outside.bin"
sudo -n -u jdc-authority -- sh -c 'printf SERVICE_DOMAIN_BYTES > "$1"' sh "$service_file"
sudo -n -u nobody -- sh -c 'printf OUTSIDE_DOMAIN_SENTINEL_UNCHANGED > "$1"' sh "$outside_file"
outside_hash="$(sudo -n -u nobody -- sha256sum "$outside_file" | cut -d ' ' -f1)"

# Execute the SAME Rust issuer root-admission implementation under the actual
# dedicated service UID, without root capabilities or privilege escalation.
# Never count a synthetic metadata predicate as native positive acceptance.
test_dir='native/authority-service/target/debug/deps'
[[ -d "$test_dir" ]] || { echo E_ISSUER_TEST_BINARY_DIR_MISSING >&2; exit 1; }
issuer_test=''
matches=0
while IFS= read -r candidate; do
  # Consume the whole test listing: grep -q could close its pipe early,
  # falsely failing the Rust harness under set -o pipefail.
  if "$candidate" --list 2>/dev/null | grep -F 'issuer_policy::tests::issuer_issues_only_an_attested_separate_filesystem_root:' >/dev/null; then
    issuer_test="$candidate"
    matches=$((matches + 1))
  fi
done < <(find "$test_dir" -maxdepth 1 -type f -executable -name 'jdc_authority_service-*' | sort)
[[ "$matches" -eq 1 ]] || { echo E_ISSUER_TEST_BINARY_AMBIGUOUS >&2; exit 1; }
# Keep the potentially large Rust test harness OUTSIDE the strict 8 MiB
# protected data volume; pin its checksum and prevent either unprivileged
# principal from replacing it via the root-admin-owned parent.
trusted_probe="$base/jdc-issuer-root-admission-test"
sudo -n install -o root -g root -m 0555 -- "$issuer_test" "$trusted_probe"
[[ "$(sha256sum "$issuer_test" | cut -d ' ' -f1)" == "$(sudo -n sha256sum "$trusted_probe" | cut -d ' ' -f1)" ]] || {
  echo E_ISSUER_TEST_BINARY_PROVENANCE_MISMATCH >&2; exit 1;
}
sudo -n -u jdc-authority -- setpriv --no-new-privs -- env \
  JDC_T011_CUSTODIED_ROOT="$isolated" \
  "$trusted_probe" --ignored --exact \
  issuer_policy::tests::issuer_issues_only_an_attested_separate_filesystem_root --nocapture
# Only the dedicated principal may traverse this 0700 mount. Checking
# from the runner UID would incorrectly turn an enforced denial into a
# missing-file verdict.
sudo -n -u jdc-authority -- test -d "$isolated/issuer-custody-positive" || {
  echo E_ISSUER_POSITIVE_ROOT_OPERATION_MISSING >&2; exit 1;
}
if sudo -n -u nobody -- test -d "$isolated/issuer-custody-positive"; then
  echo E_ISSUER_PROTECTED_ROOT_EXPOSED_TO_ATTACKER >&2; exit 1;
fi
echo T011_STORAGE_ISSUER_ROOT_ATTESTATION_PASS

# Exercise real read, in-place rewrite, append, rename and unlink under
# BOTH valid principals. Without these positive controls, an unavailable
# executable or broken filesystem could make all adversarial denials look green.
attacker_control="$attacker/operation-control.bin"
attacker_source="$attacker/operation-source.bin"
sudo -n -u nobody -- sh -c 'printf ATTACKER_CONTROL > "$1"' sh "$attacker_control"
sudo -n -u nobody -- sh -c 'printf ATTACKER_REPLACEMENT > "$1"' sh "$attacker_source"
sudo -n -u nobody -- cat -- "$attacker_control" >/dev/null
sudo -n -u nobody -- sh -c 'printf APPENDED >> "$1"' sh "$attacker_control"
sudo -n -u nobody -- cp -- "$attacker_source" "$attacker_control"
[[ "$(sudo -n -u nobody -- cat -- "$attacker_control")" == ATTACKER_REPLACEMENT ]] || exit 1
sudo -n -u nobody -- mv -- "$attacker_control" "$attacker/operation-renamed.bin"
sudo -n -u nobody -- rm -- "$attacker/operation-renamed.bin"
service_control="$isolated/service-control.bin"
sudo -n -u jdc-authority -- cp -- "$service_file" "$service_control"
sudo -n -u jdc-authority -- cat -- "$service_control" >/dev/null
sudo -n -u jdc-authority -- sh -c 'printf APPENDED >> "$1"' sh "$service_control"
sudo -n -u jdc-authority -- cp -- "$service_file" "$service_control"
sudo -n -u jdc-authority -- mv -- "$service_control" "$isolated/service-renamed.bin"
sudo -n -u jdc-authority -- rm -- "$isolated/service-renamed.bin"
[[ "$(sudo -n -u jdc-authority -- cat -- "$service_file")" == SERVICE_DOMAIN_BYTES ]] || exit 1
service_hash="$(sudo -n -u jdc-authority -- sha256sum "$service_file" | cut -d ' ' -f1)"
service_object_id="$(sudo -n stat -c '%d:%i' -- "$service_file")"
echo 'T011_STORAGE_REAL_OPERATION_POSITIVE_CONTROLS_PASS'

expect_denied() {
  local operation="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "E_STORAGE_UNAUTHORIZED_$operation" >&2
    exit 1
  fi
}
expect_denied read sudo -n -u nobody -- cat -- "$service_file"
expect_denied rewrite sudo -n -u nobody -- sh -c 'printf INJECTED > "$1"' sh "$service_file"
expect_denied append sudo -n -u nobody -- sh -c 'printf INJECTED >> "$1"' sh "$service_file"
expect_denied rename sudo -n -u nobody -- mv -- "$service_file" "$attacker/stolen-service.bin"
expect_denied unlink sudo -n -u nobody -- rm -- "$service_file"
expect_denied create sudo -n -u nobody -- touch -- "$isolated/injected.bin"
[[ ! -e "$attacker/stolen-service.bin" && ! -e "$isolated/injected.bin" ]] || {
  echo 'E_STORAGE_PROTECTED_NAMESPACE_CHANGED' >&2; exit 1;
}
[[ "$(sudo -n -u jdc-authority -- sha256sum "$service_file" | cut -d ' ' -f1)" == "$service_hash" ]] || {
  echo 'E_STORAGE_PROTECTED_BYTES_CHANGED' >&2; exit 1;
}
[[ "$(sudo -n stat -c '%d:%i' -- "$service_file")" == "$service_object_id" ]] || {
  echo 'E_STORAGE_PROTECTED_FILE_OBJECT_CHANGED' >&2; exit 1;
}
[[ "$(sudo -n -u nobody -- sha256sum "$outside_file" | cut -d ' ' -f1)" == "$outside_hash" ]] || {
  echo 'E_STORAGE_EXTERIOR_BYTES_CHANGED' >&2; exit 1;
}
echo 'T011_STORAGE_LINUX_READ_REWRITE_APPEND_RENAME_DENIED'

# The attack principal MUST succeed at a same-device hard link first.
sudo -n -u nobody -- ln -- "$outside_file" "$attacker/positive-link.bin"
[[ "$(sudo -n stat -c %d:%i "$outside_file")" == "$(sudo -n stat -c %d:%i "$attacker/positive-link.bin")" ]] || exit 1
sudo -n -u nobody -- rm -- "$attacker/positive-link.bin"
echo 'T011_STORAGE_SAME_VOLUME_HARDLINK_PASS'
# An unprivileged attacker must not enter the service-owned domain.
if sudo -n -u nobody -- ln -- "$outside_file" "$isolated/attacker.bin" 2>/dev/null; then
  echo 'E_STORAGE_ATTACKER_CROSSED_SERVICE_DOMAIN' >&2; exit 1
fi
# Even root cannot create a hard link across these actual mount devices.
# Verify EXDEV specifically so an unrelated permission failure cannot pass.
error="$(sudo -n env LC_ALL=C ln -- "$outside_file" "$isolated/admin-attempt.bin" 2>&1)" && {
  echo 'E_STORAGE_CROSS_VOLUME_HARDLINK_ALLOWED' >&2; exit 1;
}
grep -Fq 'Invalid cross-device link' <<< "$error" || {
  echo "E_STORAGE_WRONG_HARDLINK_FAILURE: $error" >&2; exit 1;
}
if sudo -n env LC_ALL=C ln -- "$service_file" "$attacker/reverse.bin" 2>/dev/null; then
  echo 'E_STORAGE_REVERSE_LINK_ALLOWED' >&2; exit 1
fi
[[ ! -e "$isolated/attacker.bin" && ! -e "$isolated/admin-attempt.bin" &&
   ! -e "$attacker/reverse.bin" ]] || exit 1
echo 'T011_STORAGE_CROSS_VOLUME_HARDLINK_DENIED'
# Separate filesystems do not prove object provenance when an administrator
# can import a foreign inode through a bind mount. This is a privileged
# counterexample, NOT an unprivileged attacker bypass or product acceptance.
sudo -n -u nobody -- chmod 0644 "$outside_file"
if sudo -n -u jdc-authority -- cat "$outside_file" >/dev/null 2>&1; then
  echo 'E_STORAGE_SERVICE_CAN_READ_PRIVATE_OUTSIDE_PATH' >&2; exit 1
fi
bind_alias="$isolated/admin-import.bin"
sudo -n -u jdc-authority -- sh -c ': > "$1"' sh "$bind_alias"
sudo -n mount --bind "$outside_file" "$bind_alias"
findmnt --kernel --mountpoint "$bind_alias" --noheadings --output TARGET >/dev/null || {
  echo 'E_STORAGE_BIND_MOUNT_NOT_ESTABLISHED' >&2; exit 1;
}
[[ "$(sudo -n stat -c %d:%i "$outside_file")" == "$(sudo -n stat -c %d:%i "$bind_alias")" ]] || {
  echo 'E_STORAGE_BIND_ALIAS_OBJECT_IDENTITY_MISMATCH' >&2; exit 1;
}
[[ "$(sudo -n -u jdc-authority -- cat "$bind_alias")" == OUTSIDE_DOMAIN_SENTINEL_UNCHANGED ]] || {
  echo 'E_STORAGE_BIND_ALIAS_SERVICE_CANNOT_READ_EXTERIOR' >&2; exit 1;
}
echo 'T011_STORAGE_ADMIN_BIND_ALIAS_EXPOSES_OUTSIDE_OBJECT_NONRELEASE'
# The bind alias is another mount path, not a hard link. A link-count
# postcheck alone therefore cannot distinguish this imported file object.
[[ "$(sudo -n stat -c %h "$outside_file")" == 1 &&
   "$(sudo -n stat -c %h "$bind_alias")" == 1 ]] || {
  echo 'E_STORAGE_BIND_ALIAS_UNEXPECTED_LINK_COUNT' >&2; exit 1;
}
# Exercise the kernel's openat2 NO_XDEV policy on an FD for the *already
# opened* authorized directory. Verify a real positive read and EXDEV for
# the imported alias. Never accept unrelated permission failures as EXDEV.
probe_source="$(realpath -e native/authority-service/target/debug/examples/linux_openat2_mount_probe)"
[[ -f "$probe_source" && -x "$probe_source" ]] || {
  echo 'E_STORAGE_OPENAT2_PROBE_MISSING' >&2; exit 1;
}
# The fixture service identity cannot necessarily traverse a CI checkout.
# Install the exact compiled probe inside its own isolated, service-owned
# volume and require byte-for-byte provenance before executing it.
probe_path="$isolated/linux_openat2_mount_probe"
sudo -n install -o jdc-authority -g jdc-authority -m 0500 -- "$probe_source" "$probe_path"
probe_hash="$(sha256sum "$probe_source" | cut -d ' ' -f1)"
[[ "$(sudo -n sha256sum "$probe_path" | cut -d ' ' -f1)" == "$probe_hash" ]] || {
  echo 'E_STORAGE_OPENAT2_PROBE_HASH_MISMATCH' >&2; exit 1;
}
sudo -n -u jdc-authority -- "$probe_path" "$isolated" service.bin allow
sudo -n -u jdc-authority -- "$probe_path" "$isolated" admin-import.bin deny-exdev
echo 'T011_STORAGE_OPENAT2_NO_XDEV_DENIES_BIND_ALIAS_NONRELEASE'
sudo -n umount -- "$bind_alias"
if findmnt --kernel --mountpoint "$bind_alias" --noheadings --output TARGET >/dev/null; then
  echo 'E_STORAGE_BIND_ALIAS_REMAINS_MOUNTED' >&2; exit 1
fi
[[ "$(sudo -n -u nobody -- sha256sum "$outside_file" | cut -d ' ' -f1)" == "$outside_hash" ]] || exit 1
[[ "$(sudo -n -u jdc-authority -- cat "$service_file")" == SERVICE_DOMAIN_BYTES ]]
echo 'T011_STORAGE_EXTERIOR_BYTES_UNCHANGED'
echo 'T011_STORAGE_LINUX_DOMAIN_PASS_NONRELEASE'
