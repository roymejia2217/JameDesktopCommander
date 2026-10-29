#!/usr/bin/env bash
# T011 #148: disposable Linux mount/device isolation proof. NON-RELEASE.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_OS:-}" != Linux ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted || "$(id -u)" -eq 0 ]]; then
  echo 'E_STORAGE_DOMAIN_HOSTED_LINUX_REQUIRED' >&2
  exit 1
fi
command -v mountpoint >/dev/null
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
mkdir -- "$isolated" "$attacker"
chmod 0711 "$base"
sudo -n chown nobody:"$(id -gn nobody)" "$attacker"
sudo -n chmod 0700 "$attacker"
cleanup() {
  local code=$?
  trap - EXIT
  if mountpoint -q "$isolated"; then
    sudo -n umount -- "$isolated" || code=1
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
outside_hash="$(sha256sum "$outside_file" | cut -d ' ' -f1)"
# The attack principal MUST succeed at a same-device hard link first.
sudo -n -u nobody -- ln -- "$outside_file" "$attacker/positive-link.bin"
[[ "$(stat -c %d:%i "$outside_file")" == "$(stat -c %d:%i "$attacker/positive-link.bin")" ]] || exit 1
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
[[ "$(sha256sum "$outside_file" | cut -d ' ' -f1)" == "$outside_hash" ]] || exit 1
[[ "$(sudo -n -u jdc-authority -- cat "$service_file")" == SERVICE_DOMAIN_BYTES ]]
echo 'T011_STORAGE_EXTERIOR_BYTES_UNCHANGED'
echo 'T011_STORAGE_LINUX_DOMAIN_PASS_NONRELEASE'
