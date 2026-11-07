import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

// Declarative contract check. The Linux CI additionally validates the unit
// with systemd-analyze and proves DAC on an actual disposable PID 1 systemd.
test('experimental socket manager owns a non-public AF_UNIX pathname', () => {
  const path = join(import.meta.dirname, '..', '..',
    'packaging', 'experimental', 'linux', 'systemd', 'jdc-authority.socket');
  const unit = readFileSync(path, 'utf8');
  const directives = new Map();
  for (const line of unit.split(/\r?\n/)) {
    const item = line.trim();
    if (!item || item.startsWith('#') || item.startsWith('[')) continue;
    const index = item.indexOf('=');
    assert.ok(index > 0, 'invalid socket configuration line');
    const key = item.slice(0, index);
    assert.ok(!directives.has(key), 'duplicate systemd directive ' + key);
    directives.set(key, item.slice(index + 1));
  }
  const expected = {
    ListenStream: '/run/jdc-authority-ipc/authority.sock',
    FileDescriptorName: 'jdc-authority-ipc',
    SocketUser: 'jdc-authority',
    SocketGroup: 'jdc-mcp-client',
    SocketMode: '0660',
    DirectoryMode: '0755',
    Accept: 'no',
    Service: 'jdc-authority.service',
    RemoveOnStop: 'yes',
  };
  for (const [key, value] of Object.entries(expected)) {
    assert.equal(directives.get(key), value, key + ' differs from reviewed policy');
  }
  assert.ok(unit.includes('[Socket]'), 'missing explicit socket declaration');
  assert.ok(!/^\[Install\]$/m.test(unit), 'must not be user-installable');
  assert.ok(!/(?:ListenDatagram|ListenSequentialPacket|ListenNetlink|ListenMessageQueue|BindIPv6Only)=/m.test(unit),
    'no additional transports may be introduced');
});

test('experimental IPC clients use a separate provisioned Unix account and group', () => {
  const sysusers = readFileSync(join(import.meta.dirname, '..', '..',
    'packaging', 'experimental', 'linux', 'sysusers.d', 'jdc-authority.conf'), 'utf8');
  const declared = sysusers.split(/\r?\n/).map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
  assert.equal(declared.length, 2,
    'exactly two independent system identities required');
  assert.ok(declared.includes('u jdc-mcp-client - "JDC experimental MCP IPC client" - /usr/sbin/nologin'),
    'separate locked non-login account must exist');
  assert.ok(!declared.some(line => /^[gm] /.test(line)),
    'no new service group memberships or separately managed groups');
  assert.ok(!declared.some(line => line.startsWith('m jdc-authority ')),
    'service account must never be added to a client group');
});

// Regression for real Ubuntu CI: native stat expectation must be derived from
// the actual reviewed socket unit, not a stale prior group name.
test('Linux kernel socket custody assertion matches declared SocketUser and SocketGroup', () => {
  const base = join(import.meta.dirname, '..', '..');
  const socket = readFileSync(join(base,
    'packaging', 'experimental', 'linux', 'systemd', 'jdc-authority.socket'), 'utf8');
  const acceptance = readFileSync(join(base,
    'test', 'security', 't011-systemd-socket-custody-acceptance.sh'), 'utf8');
  const unitLines = socket.split(/\r?\n/).map(line => line.trim());
  const user = unitLines.find(line => line.startsWith('SocketUser='))?.slice('SocketUser='.length);
  const group = unitLines.find(line => line.startsWith('SocketGroup='))?.slice('SocketGroup='.length);
  const actualCheck = acceptance.split(/\r?\n/).find(line =>
    line.includes("stat -c '%U:%G'") && line.includes('"$socket_path"') && line.includes("!= '"));
  const expected = actualCheck?.match(/!= '([^']+)'/)?.[1];
  assert.ok(user && group && expected, 'required real socket ownership assertion missing');
  assert.equal(expected, `${user}:${group}`,
    'test acceptance must compare actual native SocketUser/SocketGroup, not a stale account');
});

test('native systemd FD3 exercise rejects a different descriptor name before accepting reviewed one', () => {
  const source = readFileSync(join(import.meta.dirname, 't011-systemd-fd3-acceptance.sh'), 'utf8');
  assert.ok(source.includes('--fdname=untrusted-fd3'),
    'official systemd-socket-activate must exercise an admitted but misnamed FD3');
  assert.ok(source.includes('E_FD3_WRONG_NAME_ACCEPTED'),
    'CI must fail if the Linux observer accepts the misnamed descriptor');
  assert.ok(source.includes('E_ACTIVATION_UNVERIFIED'),
    'misnamed FD3 must produce the fail-closed native response');
  assert.ok(source.includes('--fdname=jdc-authority-ipc'),
    'the original correct-name positive control must be preserved');
});
