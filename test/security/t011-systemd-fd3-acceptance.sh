#!/usr/bin/env bash
# Research-only, GitHub-hosted Ubuntu proof using the official systemd
# socket-activation test utility. No production unit or service is activated.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != 'true' ||
      "${RUNNER_OS:-}" != 'Linux' ||
      "${RUNNER_ENVIRONMENT:-}" != 'github-hosted' ||
      "$(id -u)" -eq 0 ]]; then
  printf '%s\n' 'E_FD3_DISPOSABLE_LINUX_RUNNER_REQUIRED' >&2
  exit 1
fi

probe="$(realpath -e -- native/authority-service/target/debug/examples/systemd_activation_probe)"
test -x "$probe"
command -v systemd-socket-activate >/dev/null

private="$(mktemp -d)"
chmod 700 "$private"
test "$(stat -c '%a' "$private")" = '700'
socket="$private/authority.sock"
log="$private/activation.log"
manager=''

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$manager" ]] && kill -0 "$manager" 2>/dev/null; then
    kill -TERM "$manager" 2>/dev/null || :
    wait "$manager" 2>/dev/null || :
  fi
  if [[ -S "$socket" ]]; then rm -f -- "$socket"; fi
  rm -f -- "$log"
  rmdir -- "$private" || status=1
  exit "$status"
}
trap cleanup EXIT

# A callable example is not proof of activation: with no manager-provided
# descriptors, it MUST reject before observing a listener.
if "$probe" "$socket" > "$log" 2>&1 ||
   ! grep -Fxq 'E_ACTIVATION_UNVERIFIED' "$log"; then
  printf '%s\n' 'E_FD3_FALSE_POSITIVE_NO_MANAGER' >&2
  exit 1
fi

: > "$log"
systemd-socket-activate --listen="$socket" --fdname=jdc-authority-ipc \
  "$probe" "$socket" > "$log" 2>&1 &
manager=$!

# The official tool creates the socket and passes descriptor 3 on connect.
# Bounded readiness logic is needed only on disposable CI, not in production.
python3 - "$socket" <<'PY'
import socket
import sys
import time

path = sys.argv[1]
deadline = time.monotonic() + 5.0
while True:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(1.0)
        client.connect(path)
        break
    except (FileNotFoundError, ConnectionRefusedError):
        client.close()
        if time.monotonic() >= deadline:
            raise SystemExit("E_FD3_SOCKET_NOT_READY")
        time.sleep(0.05)
    else:
        client.close()
client.close()
PY

# Tail the official test utility's output with a bounded deadline. Require
# success from the actual child, never from a fabricated environment string.
if ! timeout 8s sh -c 'tail -n +1 -f "$1" | grep -m 1 -Fx "$2"' sh \
  "$log" 'T011_SYSTEMD_FD3_NAMED_KERNEL_SHAPE_OBSERVED_NO_AUTHORITY' \
  >/dev/null; then
  cat "$log" >&2
  printf '%s\n' 'E_FD3_INHERITED_DESCRIPTOR_NOT_VERIFIED' >&2
  exit 1
fi

if grep -Fq 'E_ACTIVATION_UNVERIFIED' "$log"; then
  printf '%s\n' 'E_FD3_MIXED_SUCCESS_AND_DENIAL' >&2
  exit 1
fi
printf '%s\n' 'T011_REAL_SYSTEMD_TOOL_FD3_ACCEPTANCE_PASS_NONRELEASE'
