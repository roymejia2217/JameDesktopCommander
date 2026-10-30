#!/usr/bin/env bash
# T011 #148: real privileged writable same-device directory bind-mount attack.
# Restricted to disposable GitHub-hosted Ubuntu. No installed JDC service used.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_OS:-}" != Linux ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted || "$(id -u)" == 0 ]]; then
  echo E_T011_MKDIR_DISPOSABLE_LINUX_RUNNER_REQUIRED >&2
  exit 1
fi
sudo -n true
fixture="$(mktemp -d "${RUNNER_TEMP:?}/jdc-t011-mkdir.XXXXXXXX")"
chmod 0700 "$fixture"
allowed="$fixture/allowed"
outside="$fixture/outside"
alias="$allowed/alias"
mkdir -p -- "$alias" "$outside"
chmod 0700 "$allowed" "$outside" "$alias"
cleanup() {
  local code=$?
  trap - EXIT
  if findmnt -rn --kernel --mountpoint "$alias" >/dev/null 2>&1; then
    sudo -n umount -- "$alias" || code=1
  fi
  if findmnt -rn --kernel --mountpoint "$alias" >/dev/null 2>&1; then
    echo E_T011_MKDIR_MOUNT_CLEANUP_FAILED >&2
    exit 1
  fi
  if [[ -e "$outside/jdc-escaped-directory" ]]; then
    echo E_T011_MKDIR_OUTSIDE_MUTATED >&2
    code=1
  fi
  rm -rf -- "$fixture" || code=1
  exit "$code"
}
trap cleanup EXIT
# An ordinary local mutation MUST work in the outside directory, proving a
# denial cannot be attributed to a read-only target or permission failure.
mkdir -- "$outside/positive-control"
rmdir -- "$outside/positive-control"
[[ "$(stat -c '%d' "$allowed")" == "$(stat -c '%d' "$outside")" ]] || {
  echo E_T011_MKDIR_SAME_DEVICE_REQUIRED >&2
  exit 1
}
sudo -n mount --bind -- "$outside" "$alias"
findmnt -rn --kernel --mountpoint "$alias" >/dev/null || {
  echo E_T011_MKDIR_BIND_NOT_ACTIVE >&2
  exit 1
}
[[ "$(stat -c '%d:%i' "$outside")" == "$(stat -c '%d:%i' "$alias")" ]] || {
  echo E_T011_MKDIR_ALIAS_OBJECT_DIFFERENT >&2
  exit 1
}
[[ ! -e "$outside/jdc-escaped-directory" ]] || exit 1
echo T011_MKDIR_REAL_WRITABLE_SAME_DEVICE_BIND_ATTACK_READY
JDC_T011_MKDIR_MOUNT_FIXTURE="$fixture" \
  cargo +1.91.1 test --locked --manifest-path native/authority-service/Cargo.toml \
    --lib handle_mkdir::tests::descendant_mkdir_refuses_real_same_device_bind_mount \
    -- --ignored --exact --nocapture
[[ ! -e "$outside/jdc-escaped-directory" ]] || {
  echo E_T011_MKDIR_OUTSIDE_MUTATED >&2
  exit 1
}
[[ -d "$allowed/legitimate/nested" ]] || exit 1
echo T011_MKDIR_WRITABLE_BIND_MOUNT_DENIED_OUTSIDE_UNCHANGED
