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

# sudo intentionally substitutes a restricted PATH for the target principal.
# Carry the exact setup-node executable across the identity boundary instead
# of silently invoking an unrelated system Node binary.
node_binary="$(realpath -e -- "$(command -v node)")"
if [[ "$("$node_binary" --version)" != 'v22.19.0' ||
      "$(sudo -n -u jdc-mcp-client -- "$node_binary" --version)" != 'v22.19.0' ]]; then
  printf '%s\n' 'E_ISSUER_READ_E2E_NODE_VERSION_MISMATCH' >&2
  exit 1
fi

fixture='native/authority-store/target/debug/examples/issuer_read_fixture'
probe='native/authority-service/target/debug/examples/linux_issuer_read_probe'
contract_source="$(realpath -e -- dist/security/authority-frame-contract.js)"
operation_contract_source="$(realpath -e -- dist/security/authority-operation-contract.js)"
read_client_source="$(realpath -e -- test/security/support/authority-read-client.mjs)"
[[ -x "$fixture" && -x "$probe" &&
   -r "$contract_source" && -r "$operation_contract_source" &&
   -r "$read_client_source" ]] || {
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
read_root_two="$state_dir/read-root-two"
socket_dir='/run/jdc-authority-ipc'
socket_path="$socket_dir/authority.sock"
service_unit='/run/systemd/system/jdc-authority.service'
socket_unit='/run/systemd/system/jdc-authority.socket'
dropin_dir='/run/systemd/system/jdc-authority.service.d'
dropin='/run/systemd/system/jdc-authority.service.d/read-e2e.conf'
installed_probe='/usr/libexec/jdc/jdc-authority-read-e2e'
contract_dir='/usr/libexec/jdc/read-e2e-contract'
installed_contract="$contract_dir/authority-frame-contract.js"
installed_operation_contract="$contract_dir/authority-operation-contract.js"
installed_read_client="$contract_dir/authority-read-client.mjs"
service_source="$(realpath -e -- packaging/experimental/linux/systemd/jdc-authority.service)"
socket_source="$(realpath -e -- packaging/experimental/linux/systemd/jdc-authority.socket)"

if [[ -e "$admin_dir" || -L "$admin_dir" ||
      -e "$service_unit" || -L "$service_unit" ||
      -e "$socket_unit" || -L "$socket_unit" ||
      -e "$dropin_dir" || -L "$dropin_dir" ||
      -e "$installed_probe" || -L "$installed_probe" ||
      -e "$contract_dir" || -L "$contract_dir" ||
      -e "$socket_dir" || -L "$socket_dir" ]]; then
  printf '%s\n' 'E_ISSUER_READ_E2E_PREEXISTING_STATE' >&2
  exit 1
fi
state_preexisting=0
if [[ -d "$state_dir" ]]; then
  state_preexisting=1
  [[ "$(stat -c '%u:%g:%a' "$state_dir")" == "$service_uid:$service_gid:700" ]] || exit 1
  [[ ! -e "$state_dir/claims.sqlite3" && ! -e "$read_root" &&
     ! -e "$read_root_two" ]] || exit 1
else
  sudo -n install -d -o jdc-authority -g jdc-authority -m 0700 -- "$state_dir"
fi

private="$(mktemp -d)"
chmod 700 "$private"
policy_source="$private/policy.sqlite3"
anchor_source="$private/policy-anchor"
replay_source="$private/claims.sqlite3"
payload_source="$private/inside.bin"
second_payload_source="$private/second.bin"
printf '\x00\xff\x81\x2aJDC\n' > "$payload_source"

printf '\x02\x00\x43\x2aSECOND\n' > "$second_payload_source"

cleanup() {
  local code=$?
  trap - EXIT
  sudo -n systemctl stop jdc-authority.socket jdc-authority.service >/dev/null 2>&1 || :
  sudo -n systemctl reset-failed jdc-authority.service >/dev/null 2>&1 || :
  sudo -n rm -rf -- "$dropin_dir" "$contract_dir" || code=1
  sudo -n rm -f -- "$service_unit" "$socket_unit" "$installed_probe" || code=1
  sudo -n systemctl daemon-reload || code=1
  sudo -n rm -rf -- "$admin_dir" "$read_root" "$read_root_two" || code=1
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
sudo -n install -d -o jdc-authority -g jdc-authority -m 0700 -- "$read_root_two"
sudo -n install -o jdc-authority -g jdc-authority -m 0600 -- "$second_payload_source" "$read_root_two/inside2.bin"
sudo -n install -D -o root -g root -m 0755 -- "$probe" "$installed_probe"
sudo -n install -d -o root -g root -m 0755 -- "$contract_dir"
sudo -n install -o root -g root -m 0644 -- "$contract_source" "$installed_contract"
sudo -n install -o root -g root -m 0644 -- "$operation_contract_source" "$installed_operation_contract"
sudo -n install -o root -g root -m 0644 -- "$read_client_source" "$installed_read_client"
sudo -n cmp -s -- "$contract_source" "$installed_contract"
sudo -n cmp -s -- "$operation_contract_source" "$installed_operation_contract"
sudo -n cmp -s -- "$read_client_source" "$installed_read_client"
sudo -n -u jdc-mcp-client -- test -r "$installed_contract"
sudo -n -u jdc-mcp-client -- test -r "$installed_operation_contract"
sudo -n -u jdc-mcp-client -- test -r "$installed_read_client"
[[ "$(stat -c '%U:%G:%a' "$contract_dir")" == 'root:root:755' &&
   "$(stat -c '%U:%G:%a' "$installed_contract")" == 'root:root:644' &&
   "$(stat -c '%U:%G:%a' "$installed_operation_contract")" == 'root:root:644' &&
   "$(stat -c '%U:%G:%a' "$installed_read_client")" == 'root:root:644' ]] || exit 1
read_client="$installed_read_client"
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

sudo -n -u jdc-mcp-client -- "$node_binary" --input-type=module - "$read_client" "$installed_contract" "$installed_operation_contract" <<'NODE'
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

const [readClientPath, contractPath, operationContractPath] = process.argv.slice(2);
assert.equal(process.version, 'v22.19.0', 'E_ISSUER_READ_E2E_NODE_VERSION_MISMATCH');
const { createIssuerReadClient } =
  await import(pathToFileURL(readClientPath).href);
const frameContract = await import(pathToFileURL(contractPath).href);
const operationContract = await import(pathToFileURL(operationContractPath).href);
const { requestIssuerOwnedRead } =
  createIssuerReadClient({ ...frameContract, ...operationContract });
const request = JSON.parse(
  '{"version":1,"kind":"read-file","requestId":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","rootRef":"0123456789abcdef0123456789abcdef","relativePath":"inside.bin"}',
);
const reply = await requestIssuerOwnedRead(request);
assert.equal(reply.status, 'ok');
if (reply.status !== 'ok') throw new Error('issuer denied canonical read');
assert.deepEqual(reply.bytes, Buffer.from([0, 255, 0x81, 42, 74, 68, 67, 10]));
console.log('T011_NODE_MCP_CLIENT_RECEIVED_EXACT_BINARY_READ_REPLY');
// Same broker process, retained native root and authenticated OS client,
// but a different canonical read request and independently named file.
const secondRequest = {
  ...request,
  requestId: '22222222-2222-4222-8222-222222222222',
  relativePath: 'inside2.bin',
  rootRef: 'fedcba9876543210fedcba9876543210',
};
const secondReply = await requestIssuerOwnedRead(secondRequest);
assert.equal(secondReply.status, 'ok', 'second sequential issuer read denied');
assert.deepEqual(
  secondReply.bytes,
  Buffer.concat([Buffer.from([2, 0, 0x43, 0x2a]), Buffer.from('SECOND\n')]),
);
console.log('T011_ISSUER_READ_E2E_SEQUENTIAL_SECOND_READ_PASS');
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

sudo -n -u jdc-authority -- python3 - "$state_dir/claims.sqlite3" <<'PY'
import sqlite3
import sys

db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
rows = db.execute(
    "SELECT hex(epoch), hex(request) FROM replay_claims ORDER BY epoch, request"
).fetchall()
expected = [
    ("0000000000000001", "11111111111141118111111111111111"),
    ("0000000000000001", "22222222222242228222222222222222"),
]
if rows != expected:
    raise SystemExit(f"E_ISSUER_READ_E2E_REPLAY_NOT_DURABLE:{rows!r}")
print("T011_ISSUER_READ_E2E_DURABLE_REPLAY_CLAIM_PASS")
PY

[[ "$(sudo -n stat -c '%u:%g:%a:%h' "$state_dir/claims.sqlite3")" == \
   "$service_uid:$service_gid:600:1" ]] || exit 1
[[ "$(sudo -n stat -c '%u:%g:%a:%h' "$read_root/inside.bin")" == \
   "$service_uid:$service_gid:600:1" ]] || exit 1
# The independently root-provisioned policy contains exactly two roots.
# A syntactically valid but UNAPPROVED third rootRef must be denied before any
# replay identity is consumed or outside filesystem bytes can be disclosed.
# A fresh service activation after two successful reads tests the real broker.
sudo -n systemctl stop jdc-authority.service
[[ "$(sudo -n systemctl show -P ActiveState jdc-authority.socket)" == 'active' &&
   -S "$socket_path" ]] || exit 1
sudo -n -u jdc-mcp-client -- "$node_binary" --input-type=module - "$read_client" "$installed_contract" "$installed_operation_contract" <<'NODE'
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

const [clientPath, framePath, operationPath] = process.argv.slice(2);
const { createIssuerReadClient } = await import(pathToFileURL(clientPath).href);
const frames = await import(pathToFileURL(framePath).href);
const operations = await import(pathToFileURL(operationPath).href);
const { requestIssuerOwnedRead } = createIssuerReadClient({ ...frames, ...operations });
const unknownRootReply = await requestIssuerOwnedRead({
  version: 1,
  kind: 'read-file',
  requestId: '33333333-3333-4333-8333-333333333333',
  expectedEpoch: '1',
  rootRef: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
  relativePath: 'inside.bin',
});
assert.deepEqual(unknownRootReply, { version: 1, status: 'denied' });
console.log('T011_ISSUER_READ_E2E_UNAPPROVED_ROOT_REF_DENIED');
NODE

# A new one-shot systemd service invocation must also reject replay of an
# already committed requestId. The original files and SQLite ledger survive.
sudo -n systemctl stop jdc-authority.service
[[ "$(sudo -n systemctl show -P ActiveState jdc-authority.socket)" == 'active' &&
   -S "$socket_path" ]] || exit 1
sudo -n -u jdc-mcp-client -- "$node_binary" --input-type=module - "$read_client" "$installed_contract" "$installed_operation_contract" <<'NODE'
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

const [clientPath, framePath, operationPath] = process.argv.slice(2);
const { createIssuerReadClient } = await import(pathToFileURL(clientPath).href);
const frames = await import(pathToFileURL(framePath).href);
const operations = await import(pathToFileURL(operationPath).href);
const { requestIssuerOwnedRead } = createIssuerReadClient({ ...frames, ...operations });
const request = JSON.parse(
  '{"version":1,"kind":"read-file","requestId":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","rootRef":"0123456789abcdef0123456789abcdef","relativePath":"inside.bin"}',
);
const replay = await requestIssuerOwnedRead(request);
assert.deepEqual(replay, { version: 1, status: 'denied' });
console.log('T011_ISSUER_READ_E2E_REPLAY_REJECTED_AFTER_RESTART');
NODE

sudo -n -u jdc-authority -- python3 - "$state_dir/claims.sqlite3" <<'PY'
import sqlite3
import sys

db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
rows = db.execute(
    "SELECT hex(epoch), hex(request) FROM replay_claims ORDER BY epoch, request"
).fetchall()
expected = [
    ("0000000000000001", "11111111111141118111111111111111"),
    ("0000000000000001", "22222222222242228222222222222222"),
]
if rows != expected:
    raise SystemExit(f"E_ISSUER_READ_E2E_REPLAY_LEDGER_CHANGED:{rows!r}")
print("T011_ISSUER_READ_E2E_REPLAY_LEDGER_UNCHANGED")
PY
sudo -n cmp -s -- "$payload_source" "$read_root/inside.bin"
sudo -n cmp -s -- "$second_payload_source" "$read_root_two/inside2.bin"
printf '%s\n' 'T011_REAL_NODE_TO_ISSUER_READ_E2E_PASS_NONRELEASE'
