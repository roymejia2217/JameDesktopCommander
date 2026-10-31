#!/usr/bin/env bash
# Disposable GitHub-hosted Ubuntu systemd socket DACL/custody acceptance.
# Not an installer. Does not activate privileged filesystem authority.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != 'true' ||
      "${RUNNER_OS:-}" != 'Linux' ||
      "${RUNNER_ENVIRONMENT:-}" != 'github-hosted' ||
      "$(id -u)" -eq 0 ||
      "$(cat /proc/1/comm)" != 'systemd' ]]; then
  printf '%s\n' 'E_SOCKET_EPHEMERAL_SYSTEMD_RUNNER_REQUIRED' >&2
  exit 1
fi
sudo -n true
command -v jq >/dev/null
getent passwd jdc-authority >/dev/null
getent passwd jdc-mcp-client >/dev/null
getent group jdc-mcp-client >/dev/null
getent passwd nobody >/dev/null

service_uid="$(id -u jdc-authority)"
service_gid="$(id -g jdc-authority)"
client_uid="$(id -u jdc-mcp-client)"
client_gid="$(id -g jdc-mcp-client)"
if [[ "$client_uid" -eq "$service_uid" || "$client_uid" -eq 0 ||
      "$client_gid" -eq "$(id -g jdc-authority)" ||
      "$(id -gn jdc-mcp-client)" != 'jdc-mcp-client' ]]; then
  printf '%s\n' 'E_SOCKET_CLIENT_PRINCIPAL_SEPARATION_MISSING' >&2
  exit 1
fi

socket_name='jdc-authority.socket'
service_name='jdc-authority.service'
socket_unit="/run/systemd/system/$socket_name"
service_unit="/run/systemd/system/$service_name"
socket_path='/run/jdc-authority-ipc/authority.sock'
socket_dir='/run/jdc-authority-ipc'
unit_source="$(realpath -e -- packaging/experimental/linux/systemd/jdc-authority.socket)"
service_source="$(realpath -e -- packaging/experimental/linux/systemd/jdc-authority.service)"
binary='/usr/libexec/jdc/jdc-authority-service'

# Fail closed on stale paths/foreign files. Never overwrite running host units.
if [[ -e "$socket_unit" || -L "$socket_unit" ||
      -e "$service_unit" || -L "$service_unit" ||
      -e "$socket_dir" || -L "$socket_dir" ||
      ! -x "$binary" ||
      "$(stat -c '%U:%G' "$binary")" != 'root:root' ]]; then
  printf '%s\n' 'E_SOCKET_UNEXPECTED_RUNNER_STATE' >&2
  exit 1
fi

cleanup() {
  local outcome=$?
  trap - EXIT
  sudo -n systemctl stop "$socket_name" "$service_name" >/dev/null 2>&1 || outcome=1
  sudo -n systemctl reset-failed "$service_name" >/dev/null 2>&1 || outcome=1
  sudo -n rm -f -- "$socket_unit" "$service_unit" || outcome=1
  sudo -n systemctl daemon-reload || outcome=1
  if [[ -e "$socket_path" || -L "$socket_path" ]]; then
    sudo -n rm -f -- "$socket_path" || outcome=1
    outcome=1
  fi
  if [[ -d "$socket_dir" ]]; then
    sudo -n rmdir -- "$socket_dir" || outcome=1
  fi
  exit "$outcome"
}
trap cleanup EXIT
# Explicitly staged only within /run/systemd/system on the disposable runner.
sudo -n install -m 0644 "$service_source" "$service_unit"
sudo -n install -m 0644 "$unit_source" "$socket_unit"
sudo -n systemctl daemon-reload
sudo -n systemd-analyze verify "$socket_unit" "$service_unit"
sudo -n systemctl start "$socket_name"

if [[ "$(sudo -n systemctl show -P ActiveState "$socket_name")" != 'active' ||
      "$(sudo -n systemctl show -P SubState "$socket_name")" != 'listening' ||
      ! -S "$socket_path" ]]; then
  printf '%s\n' 'E_SOCKET_MANAGER_NOT_LISTENING' >&2
  exit 1
fi
if [[ "$(stat -c '%U:%G' "$socket_path")" != 'jdc-authority:jdc-mcp-client' ||
      "$(stat -c '%a' "$socket_path")" != '660' ||
      "$(stat -c '%U:%G' "$socket_dir")" != 'root:root' ||
      "$(stat -c '%a' "$socket_dir")" != '755' ]]; then
  printf '%s\n' 'E_SOCKET_MANAGER_CUSTODY_INCORRECT' >&2
  exit 1
fi

socket_identity="$(stat -c '%d:%i' "$socket_path")"

# A real untrusted principal must have ordinary filesystem write access in
# its own directory; failure to sudo or to start Python is not a valid denial.
other_dir="$(sudo -n -u nobody mktemp -d /tmp/jdc-authority-socket-client.XXXXXXXX)"
if [[ "$other_dir" != /tmp/jdc-authority-socket-client.* ]]; then
  printf '%s\n' 'E_SOCKET_OTHER_PRINCIPAL_POSITIVE_CONTROL_MISSING' >&2
  exit 1
fi
sudo -n -u nobody touch "$other_dir/positive-control"
sudo -n -u nobody test -f "$other_dir/positive-control"
sudo -n -u nobody rm -- "$other_dir/positive-control"
sudo -n -u nobody rmdir -- "$other_dir"

# Negative control must reach the kernel and receive EACCES/EPERM. A transport
# crash, timeout or missing executable is never accepted as policy denial.
sudo -n -u nobody python3 -c '
import errno
import socket
import sys
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    client.connect(sys.argv[1])
except OSError as exc:
    if exc.errno not in (errno.EACCES, errno.EPERM):
        raise
    print("KERNEL_SOCKET_DAC_DENIED")
else:
    raise SystemExit("E_SOCKET_UNAUTHORIZED_CONNECT_SUCCEEDED")
finally:
    client.close()
' "$socket_path"

if sudo -n -u nobody -- rm -- "$socket_path" >/dev/null 2>&1 ||
   sudo -n -u nobody -- ln -s /tmp "$socket_dir/forged.sock" >/dev/null 2>&1 ||
   [[ -e "$socket_dir/forged.sock" || -L "$socket_dir/forged.sock" ]] ||
   [[ "$(stat -c '%d:%i' "$socket_path")" != "$socket_identity" ]]; then
  printf '%s\n' 'E_SOCKET_UNTRUSTED_NAMESPACE_MUTATION' >&2
  exit 1
fi
# Distinct authenticated *connect admission* via OS group is deliberately NOT
# filesystem permission. The client cannot access service-private state.
state_dir='/var/lib/jdc-authority'
if [[ ! -d "$state_dir" ]] ||
   sudo -n -u jdc-mcp-client -- test -r "$state_dir" ||
   sudo -n -u jdc-mcp-client -- test -w "$state_dir"; then
  printf '%s\n' 'E_SOCKET_CLIENT_INHERITED_SERVICE_STORAGE_AUTHORITY' >&2
  exit 1
fi

# Record the previous service invocation. The next accepted client connection
# must provoke a NEW systemd activation; an old deny log is insufficient proof.
before_invocation="$(sudo -n systemctl show -P InvocationID "$service_name")"

sudo -n -u jdc-mcp-client python3 -c '
import socket
import struct
import sys

# Canonical C4d request bytes; admitted transport alone never authorizes mkdir.
payload = b"""{"version":1,"kind":"create-directory","requestId":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","rootRef":"0123456789abcdef0123456789abcdef","relativePath":"must-not-create"}"""
frame = struct.pack("!I", len(payload)) + payload

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(2)
try:
    client.connect(sys.argv[1])
    client.sendall(frame)
    client.shutdown(socket.SHUT_WR)
    print("SEPARATE_MCP_CLIENT_CONNECT_POSITIVE_NOT_AUTHORIZATION")
finally:
    client.close()
' "$socket_path"

# Group membership grants only connect(), not mutation of the protected
# root-owned socket pathname or its enclosing directory.
if sudo -n -u jdc-mcp-client -- rm -- "$socket_path" >/dev/null 2>&1 ||
   sudo -n -u jdc-mcp-client -- ln -s /tmp "$socket_dir/client-forged.sock" >/dev/null 2>&1 ||
   [[ -e "$socket_dir/client-forged.sock" || -L "$socket_dir/client-forged.sock" ]] ||
   [[ "$(stat -c '%d:%i' "$socket_path")" != "$socket_identity" ]]; then
  printf '%s\n' 'E_SOCKET_CLIENT_NAMESPACE_MUTATION' >&2
  exit 1
fi

# Owner and separate client can connect; other principal cannot. This proves
# the kernel admission ACL, NEVER authorization for a broker operation.
sudo -n -u jdc-authority python3 -c '
import socket
import sys
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(2)
try:
    client.connect(sys.argv[1])
    print("SOCKET_OWNER_CONNECT_POSITIVE")
finally:
    client.close()
' "$socket_path"

# A live listener is not automatically a trusted authority; the service
# remains its preexisting deny-only binary and must never enter RUNNING.
sudo -n systemctl stop "$socket_name"
if [[ "$(sudo -n systemctl show -P ActiveState "$socket_name")" != 'inactive' ||
      -e "$socket_path" || -L "$socket_path" ]]; then
  printf '%s\n' 'E_SOCKET_STOP_DID_NOT_REMOVE_ENDPOINT' >&2
  exit 1
fi

# The separate MCP principal transmitted one canonical C4d operation. Prove
# systemd actually invoked the service and that its policy gate denied it.
# Compare invocation IDs to reject a false PASS from earlier lifecycle logs.
after_invocation="$(sudo -n systemctl show -P InvocationID "$service_name")"
if [[ ! "$after_invocation" =~ ^[[:xdigit:]]{32}$ ||
      "$after_invocation" == "$before_invocation" ||
      "$(sudo -n systemctl show -P Result "$service_name")" != 'exit-code' ||
      "$(sudo -n systemctl show -P ExecMainStatus "$service_name")" != '1' ||
      "$(sudo -n systemctl show -P User "$service_name")" != 'jdc-authority' ||
      "$(sudo -n systemctl show -P Group "$service_name")" != 'jdc-authority' ||
      "$(sudo -n systemctl show -P Restart "$service_name")" != 'no' ||
      "$(sudo -n systemctl show -P NRestarts "$service_name")" != '0' ]]; then
  printf '%s\n' 'E_SOCKET_ACTIVATED_SERVICE_MUST_DENY' >&2
  exit 1
fi
sudo -n journalctl --sync
invocation_journal="$(sudo -n journalctl -b -u "$service_name" \
  "_SYSTEMD_INVOCATION_ID=$after_invocation" --no-pager --output=cat)"
# journald can omit _SYSTEMD_INVOCATION_ID on a short-lived stdout
# stream. Independently validate the last OS process even when the direct
# invocation tag exists. Neither an older PID nor a later reused-PID event
# is acceptable: the message must fall within the current process lifetime.
# Both forms must bind the denial to the same systemd-managed service.
exec_pid="$(sudo -n systemctl show -P ExecMainPID "$service_name")"
exec_started_us="$(sudo -n systemctl show -P ExecMainStartTimestampMonotonic "$service_name")"
exec_exited_us="$(sudo -n systemctl show -P ExecMainExitTimestampMonotonic "$service_name")"
if [[ ! "$exec_pid" =~ ^[1-9][0-9]*$ ||
      ! "$exec_started_us" =~ ^[1-9][0-9]*$ ||
      ! "$exec_exited_us" =~ ^[1-9][0-9]*$ ]] ||
   (( exec_exited_us < exec_started_us )); then
  printf '%s\n' 'E_SOCKET_LATEST_PROCESS_IDENTITY_UNAVAILABLE' >&2
  exit 1
fi
process_journal="$(sudo -n journalctl -b \
  "_PID=$exec_pid" "_UID=$service_uid" "_GID=$service_gid" \
  "_SYSTEMD_UNIT=$service_name" \
  "SYSLOG_IDENTIFIER=jdc-authority-service" --no-pager --output=json)"
pid_journal="$(jq -r --argjson minimum "$exec_started_us" \
  --argjson maximum "$exec_exited_us" '
  select(.__MONOTONIC_TIMESTAMP != null and
         ((.__MONOTONIC_TIMESTAMP | tonumber) >= $minimum) and
         ((.__MONOTONIC_TIMESTAMP | tonumber) <= $maximum) and
         (.MESSAGE == "E_POLICY_UNAVAILABLE" or
          .MESSAGE == "E_IDENTITY_REQUIRED")) | .MESSAGE
' <<< "$process_journal")"
if ! grep -Fxq 'E_POLICY_UNAVAILABLE' <<<"$pid_journal" ||
   grep -Fq 'E_IDENTITY_REQUIRED' <<<"$pid_journal"; then
  printf '%s\n' 'E_SOCKET_CURRENT_PROCESS_DENIAL_UNPROVEN' >&2
  exit 1
fi
printf '%s\n' 'T011_SOCKET_DENIAL_CORRELATED_BY_SYSTEMD_PID_NONRELEASE'
if [[ -z "$invocation_journal" ]]; then
  invocation_journal="$pid_journal"
fi
if ! grep -Fxq 'E_POLICY_UNAVAILABLE' <<<"$invocation_journal" ||
   grep -Fq 'E_IDENTITY_REQUIRED' <<<"$invocation_journal"; then
  # This remains a mandatory FAIL. Preserve exact invocation diagnostics
  # rather than treating an empty/stale journal as a passing denial.
  printf '%s\n' 'E_SOCKET_ACTIVATED_SERVICE_IDENTITY_OR_POLICY_FAILURE' >&2
  printf 'E_SOCKET_JOURNAL_DIAGNOSTICS invocation=%s\n' "$after_invocation" >&2
  printf '%s\n' "$invocation_journal" >&2
  sudo -n systemctl show "$service_name" \
    -p ActiveState -p Result -p ExecMainStatus -p InvocationID >&2
  sudo -n journalctl -b -u "$service_name" --no-pager -n 30 --output=verbose >&2
  exit 1
fi
if [[ -e "$state_dir/must-not-create" || -L "$state_dir/must-not-create" ]]; then
  printf '%s\n' 'E_SOCKET_UNAUTHORIZED_C4D_FILESYSTEM_EFFECT' >&2
  exit 1
fi
printf '%s\n' 'T011_SYSTEMD_SOCKET_DAC_AND_CUSTODY_PASS_NONRELEASE'
