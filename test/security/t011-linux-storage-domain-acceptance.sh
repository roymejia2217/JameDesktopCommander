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
probe_path="$(realpath -e native/authority-service/target/debug/examples/linux_openat2_mount_probe)"
[[ -x "$probe_path" ]] || {
  echo 'E_STORAGE_OPENAT2_PROBE_MISSING' >&2; exit 1;
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
