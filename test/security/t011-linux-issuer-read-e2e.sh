#!/usr/bin/env bash
# Disposable GitHub-hosted proof: real Node client principal -> systemd FD3 ->
# OS-attested issuer -> replay claim -> handle-bound binary read reply.
# Production jdc-authority-service remains deny-only and is not executed here.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != 'true' ||
      "${RUNNER_OS:-}" != 'Linux' ||
      "${RUNNER_ENVIRONMENT:-}" != 'github-hosted' ||
      "$(id -u)" -eq 0 ||
      "$(cat /proc/1/comm)" != 'systemd' ]]; then
  printf '%s\n' 'E_ISSUER_READ_E2E_DISPOSABLE_RUNNER_REQUIRED' >&2
  exit 1
fi
sudo -n true
for account in jdc-authority jdc-mcp-client; do
  getent passwd "$account" >/dev/null
done

fixture='native/authority-store/target/debug/examples/issuer_read_fixture'
probe='native/authority-service/target/debug/examples/linux_issuer_read_probe'
[[ -x "$fixture" && -x "$probe" ]] || {
  printf '%s\n' 'E_ISSUER_READ_E2E_BINARIES_MISSING' >&2
  exit 1
}
service_uid="$(id -u jdc-authority)"
service_gid="$(id -g jdc-authority)"
client_uid="$(id -u jdc-mcp-client)"
client_gid="$(id -g jdc-mcp-client)"
[[ "$service_uid" -gt 0 && "$client_uid" -gt 0 &&
   "$service_uid" != "$client_uid" && "$service_gid" != "$client_gid" ]] || exit 1

admin_dir='/etc/jdc-authority'
state_dir='/var/lib/jdc-authority'
read_root="$state_dir/read-root"
socket_dir='/run/jdc-authority-ipc'
socket_path="$socket_dir/authority.sock"
service_unit='/run/systemd/system/jdc-authority.service'
socket_unit='/run/systemd/system/jdc-authority.socket'
dropin_dir='/run/systemd/system/jdc-authority.service.d'
dropin='/run/systemd/system/jdc-authority.service.d/read-e2e.conf'
installed_probe='/usr/libexec/jdc/jdc-authority-read-e2e'
service_source="$(realpath -e -- packaging/experimental/linux/systemd/jdc-authority.service)"
socket_source="$(realpath -e -- packaging/experimental/linux/systemd/jdc-authority.socket)"

if [[ -e "$admin_dir" || -L "$admin_dir" ||
      -e "$service_unit" || -L "$service_unit" ||
      -e "$socket_unit" || -L "$socket_unit" ||
      -e "$dropin_dir" || -L "$dropin_dir" ||
      -e "$installed_probe" || -L "$installed_probe" ||
      -e "$socket_dir" || -L "$socket_dir" ]]; then
  printf '%s\n' 'E_ISSUER_READ_E2E_PREEXISTING_STATE' >&2
  exit 1
fi
state_preexisting=0
if [[ -d "$state_dir" ]]; then
  state_preexisting=1
  [[ "$(stat -c '%u:%g:%a' "$state_dir")" == "$service_uid:$service_gid:700" ]] || exit 1
  [[ ! -e "$state_dir/claims.sqlite3" && ! -e "$read_root" ]] || exit 1
else
  sudo -n install -d -o jdc-authority -g jdc-authority -m 0700 -- "$state_dir"
fi

private="$(mktemp -d)"
chmod 700 "$private"
policy_source="$private/policy.sqlite3"
anchor_source="$private/policy-anchor"
replay_source="$private/claims.sqlite3"
payload_source="$private/inside.bin"
printf '\x00\xff\x81\x2aJDC\n' > "$payload_source"

cleanup() {
  local code=$?
  trap - EXIT
  sudo -n systemctl stop jdc-authority.socket jdc-authority.service >/dev/null 2>&1 || :
  sudo -n systemctl reset-failed jdc-authority.service >/dev/null 2>&1 || :
  sudo -n rm -rf -- "$dropin_dir" || code=1
  sudo -n rm -f -- "$service_unit" "$socket_unit" "$installed_probe" || code=1
  sudo -n systemctl daemon-reload || code=1
  sudo -n rm -rf -- "$admin_dir" "$read_root" || code=1
  sudo -n rm -f -- "$state_dir/claims.sqlite3" "$state_dir/claims.sqlite3-journal" \
    "$state_dir/claims.sqlite3-wal" "$state_dir/claims.sqlite3-shm" || code=1
  if [[ "$state_preexisting" -eq 0 ]]; then
    sudo -n rmdir -- "$state_dir" || code=1
  fi
  if [[ -e "$socket_path" || -L "$socket_path" ]]; then
    sudo -n rm -f -- "$socket_path" || code=1
  fi
  if [[ -d "$socket_dir" ]]; then
    sudo -n rmdir -- "$socket_dir" || code=1
  fi
  rm -rf -- "$private" || code=1
  exit "$code"
}
trap cleanup EXIT

"$fixture" "$policy_source" "$anchor_source" "$replay_source"
[[ "$(wc -c < "$anchor_source")" -eq 40 ]] || exit 1
[[ "$(stat -c '%s' "$policy_source")" -ge 512 &&
   "$(stat -c '%s' "$replay_source")" -ge 512 ]] || exit 1

sudo -n install -d -o root -g root -m 0755 -- "$admin_dir"
sudo -n install -o root -g jdc-authority -m 0640 -- "$policy_source" "$admin_dir/policy.sqlite3"
sudo -n install -o root -g jdc-authority -m 0640 -- "$anchor_source" "$admin_dir/policy-anchor"
sudo -n install -o jdc-authority -g jdc-authority -m 0600 -- "$replay_source" "$state_dir/claims.sqlite3"
sudo -n install -d -o jdc-authority -g jdc-authority -m 0700 -- "$read_root"
sudo -n install -o jdc-authority -g jdc-authority -m 0600 -- "$payload_source" "$read_root/inside.bin"
sudo -n install -D -o root -g root -m 0755 -- "$probe" "$installed_probe"
sudo -n install -o root -g root -m 0644 -- "$service_source" "$service_unit"
sudo -n install -o root -g root -m 0644 -- "$socket_source" "$socket_unit"
sudo -n install -d -o root -g root -m 0755 -- "$dropin_dir"
cat > "$private/read-e2e.conf" <<EOF
[Service]
ExecStart=
ExecStart=$installed_probe
EOF
sudo -n install -o root -g root -m 0644 -- "$private/read-e2e.conf" "$dropin"

sudo -n systemctl daemon-reload
sudo -n systemd-analyze verify "$service_unit" "$socket_unit"
sudo -n systemctl start jdc-authority.socket
[[ "$(sudo -n systemctl show -P ActiveState jdc-authority.socket)" == 'active' &&
   "$(sudo -n systemctl show -P SubState jdc-authority.socket)" == 'listening' &&
   -S "$socket_path" ]] || exit 1
[[ "$(stat -c '%U:%G:%a' "$socket_path")" == 'jdc-authority:jdc-mcp-client:660' &&
   "$(stat -c '%U:%G:%a' "$socket_dir")" == 'root:root:755' ]] || exit 1

sudo -n -u jdc-mcp-client -- node - "$socket_path" <<'NODE'
const net = require('node:net');
const assert = require('node:assert/strict');
const socketPath = process.argv[2];
const payload = Buffer.from(
  '{"version":1,"kind":"read-file","requestId":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","rootRef":"0123456789abcdef0123456789abcdef","relativePath":"inside.bin"}',
  'utf8',
);
const frame = Buffer.allocUnsafe(4 + payload.length);
frame.writeUInt32BE(payload.length, 0);
payload.copy(frame, 4);
const chunks = [];
let total = 0;
const client = net.createConnection({ path: socketPath });
client.setTimeout(5000);
client.on('connect', () => {
  client.end(frame);
});
client.on('data', (chunk) => {
  total += chunk.length;
  if (total > 1024 * 1024 + 6) throw new Error('oversized authority reply');
  chunks.push(Buffer.from(chunk));
});
client.on('timeout', () => client.destroy(new Error('authority reply timeout')));
client.on('error', (error) => {
  console.error(error);
  process.exitCode = 1;
});
client.on('close', () => {
  if (process.exitCode) return;
  const reply = Buffer.concat(chunks);
  assert.ok(reply.length >= 6);
  const header = [...reply.subarray(0, 6)];
  assert.deepEqual(header, [1, 0, 0, 0, 0, 8]);
  const length = reply.readUInt32BE(2);
  assert.equal(reply.length, 6 + length);
  assert.deepEqual(reply.subarray(6), Buffer.from([0, 255, 0x81, 42, 74, 68, 67, 10]));
  console.log('T011_NODE_MCP_CLIENT_RECEIVED_EXACT_BINARY_READ_REPLY');
});
NODE

sudo -n journalctl --sync
invocation="$(sudo -n systemctl show -P InvocationID jdc-authority.service)"
[[ "$invocation" =~ ^[[:xdigit:]]{32}$ ]] || exit 1
journal="$(sudo -n journalctl -b -u jdc-authority.service \
  "_SYSTEMD_INVOCATION_ID=$invocation" --no-pager --output=cat)"
grep -Fxq 'T011_ISSUER_READ_E2E_SERVICE_PASS_NONRELEASE' <<<"$journal"
if grep -Fq 'E_ISSUER_READ_E2E_DENIED' <<<"$journal"; then
  printf '%s\n' 'E_ISSUER_READ_E2E_MIXED_SERVICE_VERDICT' >&2
  exit 1
fi

[[ "$(sudo -n stat -c '%u:%g:%a:%h' "$state_dir/claims.sqlite3")" == \
   "$service_uid:$service_gid:600:1" ]] || exit 1
[[ "$(sudo -n stat -c '%u:%g:%a:%h' "$read_root/inside.bin")" == \
   "$service_uid:$service_gid:600:1" ]] || exit 1
printf '%s\n' 'T011_REAL_NODE_TO_ISSUER_READ_E2E_PASS_NONRELEASE'
