#!/usr/bin/env bash
# T011-C4l disposable GitHub-hosted Ubuntu acceptance, never an installer.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" || "${RUNNER_OS:-}" != "Linux" ||
      "${RUNNER_ENVIRONMENT:-}" != "github-hosted" || "$(id -u)" -eq 0 ]]; then
  printf '%s\n' 'E_SYSTEMD_EPHEMERAL_RUNNER_REQUIRED' >&2
  exit 1
fi
if [[ "$(cat /proc/1/comm)" != "systemd" ]]; then
  printf '%s\n' 'E_SYSTEMD_PID1_UNAVAILABLE' >&2
  exit 1
fi

unit_name='jdc-authority.service'
unit_destination="/run/systemd/system/$unit_name"
unit_source="$(realpath -e packaging/experimental/linux/systemd/jdc-authority.service)"
state_dir='/var/lib/jdc-authority'
run_dir='/run/jdc-authority'
if [[ -e "$unit_destination" || -L "$unit_destination" ||
      -e "$state_dir" || -e "$run_dir" ]]; then
  printf '%s\n' 'E_SYSTEMD_UNEXPECTED_PREEXISTING_STATE' >&2
  exit 1
fi
if ! getent passwd jdc-authority >/dev/null; then
  printf '%s\n' 'E_SYSTEMD_SERVICE_ACCOUNT_NOT_PROVISIONED' >&2
  exit 1
fi
# The runner's manager must execute the exact binary built from this commit,
# installed as root-owned executable by the preceding governed validation.
built_binary='native/authority-service/target/debug/jdc-authority-service'
installed_binary='/usr/libexec/jdc/jdc-authority-service'
if [[ ! -x "$installed_binary" || "$(stat -c '%U:%G' "$installed_binary")" != 'root:root' ]] ||
   ! cmp -s -- "$built_binary" "$installed_binary"; then
  printf '%s\n' 'E_SYSTEMD_BINARY_PROVENANCE_MISMATCH' >&2
  exit 1
fi
sudo -n true
cleanup() {
  local result=$?
  trap - EXIT
  sudo -n systemctl stop "$unit_name" >/dev/null 2>&1 || result=1
  sudo -n systemctl reset-failed "$unit_name" >/dev/null 2>&1 || result=1
  sudo -n rm -f -- "$unit_destination" || result=1
  sudo -n systemctl daemon-reload || result=1
  exit "$result"
}
trap cleanup EXIT

sudo -n install -m 0644 "$unit_source" "$unit_destination"
sudo -n systemctl daemon-reload
# For Type=exec, a successful start request only confirms successful execve,
# not that the unit remains active. Official --wait synchronizes with actual
# termination; a standard bounded timeout prevents a broken binary from
# hanging the security job. Do not confuse the start CLI status with the
# process's final systemd Result/ExecMainStatus and journal diagnostics.
if timeout --kill-after=5s 30s sudo -n systemctl --wait start "$unit_name"; then
  :
else
  start_status=$?
  if [[ "$start_status" -eq 124 || "$start_status" -eq 137 ]]; then
    printf '%s\n' 'E_SYSTEMD_TERMINATION_TIMEOUT' >&2
    exit 1
  fi
fi

# Identity must be valid: the binary prints E_POLICY_UNAVAILABLE only after
# verify_service_identity succeeds, while invalid OS tokens print another error.
if [[ "$(sudo -n systemctl show -P Result "$unit_name")" != 'exit-code' ||
      "$(sudo -n systemctl show -P ExecMainStatus "$unit_name")" != '1' ||
      "$(sudo -n systemctl show -P User "$unit_name")" != 'jdc-authority' ||
      "$(sudo -n systemctl show -P Group "$unit_name")" != 'jdc-authority' ||
      "$(sudo -n systemctl show -P Restart "$unit_name")" != 'no' ||
      "$(sudo -n systemctl show -P NRestarts "$unit_name")" != '0' ]]; then
  printf '%s\n' 'E_SYSTEMD_FAILED_CLOSED_PROPERTIES_MISMATCH' >&2
  exit 1
fi
journal="$(sudo -n journalctl -u "$unit_name" -b --no-pager --output=cat)"
if ! grep -Fxq 'E_POLICY_UNAVAILABLE' <<<"$journal"; then
  printf '%s\n' 'E_SYSTEMD_EXPECTED_DENIAL_NOT_LOGGED' >&2
  exit 1
fi
if grep -Fq 'E_IDENTITY_REQUIRED' <<<"$journal"; then
  printf '%s\n' 'E_SYSTEMD_SERVICE_IDENTITY_INCORRECT' >&2
  exit 1
fi

if [[ "$(stat -c '%U:%G' "$state_dir")" != 'jdc-authority:jdc-authority' ||
      "$(stat -c '%a' "$state_dir")" != '700' ]]; then
  printf '%s\n' 'E_SYSTEMD_PROTECTED_STATE_PERMISSIONS' >&2
  exit 1
fi
sudo -n -u jdc-authority -- test -w "$state_dir"
if sudo -n -u nobody -- test -r "$state_dir"; then
  printf '%s\n' 'E_CUSTODY_UNAUTHORIZED_READ' >&2
  exit 1
fi
if sudo -n -u nobody -- test -w "$state_dir"; then
  printf '%s\n' 'E_CUSTODY_UNAUTHORIZED_WRITE' >&2
  exit 1
fi
if [[ "$(sudo -n systemctl show -P NoNewPrivileges "$unit_name")" != 'yes' ]]; then
  printf '%s\n' 'E_SYSTEMD_NO_NEW_PRIVILEGES_MISSING' >&2
  exit 1
fi
printf '%s\n' 'T011-C4l systemd PID1 fail-closed lifecycle: PASS (non-release)'
