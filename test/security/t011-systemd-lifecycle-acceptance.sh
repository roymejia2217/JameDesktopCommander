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
proof_built='native/authority-service/target/debug/jdc-authority-systemd-issued-proof'
client_built='native/authority-service/target/debug/jdc-authority-systemd-issued-client'
proof_installed='/usr/libexec/jdc/jdc-authority-systemd-issued-proof'
client_installed='/usr/libexec/jdc/jdc-authority-systemd-issued-client'
proof_dropin_dir="/run/systemd/system/$unit_name.d"
proof_dropin="$proof_dropin_dir/issued-origin.conf"
if [[ -e "$unit_destination" || -L "$unit_destination" ||
      -e "$state_dir" || -e "$run_dir" || -e "$proof_dropin_dir" ||
      -e "$proof_installed" || -e "$client_installed" ]]; then
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
  sudo -n rm -f -- "$proof_dropin" "$proof_installed" "$client_installed" || result=1
  if [[ -d "$proof_dropin_dir" ]]; then
    sudo -n rmdir -- "$proof_dropin_dir" || result=1
  fi
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

# RED/CI acceptance: a genuine systemd-origin service must launch and reap
# a distinct child under the protected service UID/GID. Neither executable
# may accept an ordinary runner or attacker login as that principal.
for fixture in "$proof_built" "$client_built"; do
  if [[ ! -x "$fixture" ]]; then
    printf '%s\n' 'E_SYSTEMD_ISSUED_FIXTURE_NOT_BUILT' >&2
    exit 1
  fi
done
sudo -n install -o root -g root -m 0755 "$proof_built" "$proof_installed"
sudo -n install -o root -g root -m 0755 "$client_built" "$client_installed"
if [[ "$(stat -c '%U:%G' "$proof_installed")" != 'root:root' ||
      "$(stat -c '%U:%G' "$client_installed")" != 'root:root' ]] ||
   ! cmp -s -- "$proof_built" "$proof_installed" ||
   ! cmp -s -- "$client_built" "$client_installed"; then
  printf '%s\n' 'E_SYSTEMD_ISSUED_IMAGE_PROVENANCE_MISMATCH' >&2
  exit 1
fi
if "$proof_installed" >/dev/null 2>&1; then
  printf '%s\n' 'E_SYSTEMD_INTERACTIVE_ISSUER_ACCEPTED' >&2
  exit 1
else
  [[ "$?" -eq 1 ]] || { printf '%s\n' 'E_SYSTEMD_INTERACTIVE_ISSUER_UNEXPECTED_EXIT' >&2; exit 1; }
fi
if sudo -n -u nobody -- "$client_installed" >/dev/null 2>&1; then
  printf '%s\n' 'E_SYSTEMD_ATTACKER_CHILD_ACCEPTED' >&2
  exit 1
else
  [[ "$?" -eq 1 ]] || { printf '%s\n' 'E_SYSTEMD_ATTACKER_CHILD_UNEXPECTED_EXIT' >&2; exit 1; }
fi

# The reviewed denial-only unit remains unchanged on disk. The disposable
# runner uses a root-owned runtime drop-in for the positive origin proof.
sudo -n install -d -o root -g root -m 0755 "$proof_dropin_dir"
printf '[Service]\nExecStart=\nExecStart=%s\n' "$proof_installed" |
  sudo -n tee "$proof_dropin" >/dev/null
sudo -n chown root:root "$proof_dropin"
sudo -n chmod 0644 "$proof_dropin"
if [[ "$(stat -c '%U:%G' "$proof_dropin")" != 'root:root' ]]; then
  printf '%s\n' 'E_SYSTEMD_ISSUED_DROPIN_NOT_PROTECTED' >&2
  exit 1
fi
sudo -n systemctl daemon-reload
if [[ "$(sudo -n systemctl show -P DropInPaths "$unit_name")" != "$proof_dropin" ]] ||
   ! sudo -n systemctl show -P ExecStart "$unit_name" | grep -Fq "path=$proof_installed"; then
  printf '%s\n' 'E_SYSTEMD_ISSUED_IMAGE_NOT_PINNED' >&2
  exit 1
fi
sudo -n systemctl reset-failed "$unit_name"
if timeout --kill-after=5s 30s sudo -n systemctl --wait start "$unit_name"; then
  :
else
  proof_start_status=$?
  if [[ "$proof_start_status" -eq 124 || "$proof_start_status" -eq 137 ]]; then
    printf '%s\n' 'E_SYSTEMD_ISSUED_TERMINATION_TIMEOUT' >&2
    exit 1
  fi
fi
if [[ "$(sudo -n systemctl show -P Result "$unit_name")" != 'exit-code' ||
      "$(sudo -n systemctl show -P ExecMainStatus "$unit_name")" != '6' ||
      "$(sudo -n systemctl show -P User "$unit_name")" != 'jdc-authority' ||
      "$(sudo -n systemctl show -P Group "$unit_name")" != 'jdc-authority' ||
      "$(sudo -n systemctl show -P NRestarts "$unit_name")" != '0' ]]; then
  printf '%s\n' 'E_SYSTEMD_REAL_ISSUED_CHILD_PROOF_FAILED' >&2
  exit 1
fi
proof_journal="$(sudo -n journalctl -u "$unit_name" -b --no-pager --output=cat)"
if ! grep -Fxq 'E_SYSTEMD_ISSUED_CHILD_OK' <<<"$proof_journal"; then
  printf '%s\n' 'E_SYSTEMD_ISSUED_CHILD_ORIGIN_UNOBSERVED' >&2
  exit 1
fi
printf '%s\n' 'T011-C4l systemd-issued child origin: PASS (non-release, no MCP authorization)'
