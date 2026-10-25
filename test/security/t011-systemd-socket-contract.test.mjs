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
