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
getent passwd jdc-authority >/dev/null
getent passwd jdc-mcp-client >/dev/null
getent group jdc-mcp-client >/dev/null
getent passwd nobody >/dev/null

service_uid="$(id -u jdc-authority)"
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

sudo -n -u jdc-mcp-client python3 -c '
import socket
import sys
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(2)
try:
    client.connect(sys.argv[1])
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
printf '%s\n' 'T011_SYSTEMD_SOCKET_DAC_AND_CUSTODY_PASS_NONRELEASE'
