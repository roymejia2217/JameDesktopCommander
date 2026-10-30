// Real cross-runtime C4d acceptance parity: canonical TypeScript vs native Rust.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { decodeAuthorityRequestFrame, encodeAuthorityRequestFrame }
  from '../../dist/security/authority-frame-contract.js';

const root = join(import.meta.dirname, '..', '..');
const executable = join(root, 'native', 'authority-service', 'target', 'debug',
  'examples', process.platform === 'win32' ? 'c4d_probe.exe' : 'c4d_probe');
const base = () => ({
  version: 1, kind: 'create-directory',
  requestId: '11111111-1111-4111-8111-111111111111',
  expectedEpoch: '18446744073709551615',
  rootRef: '0123456789abcdef0123456789abcdef',
  relativePath: 'project/科研',
});
function frame(data) {
  const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  const output = Buffer.allocUnsafe(4 + bytes.length);
  output.writeUInt32BE(bytes.length, 0);
  bytes.copy(output, 4);
  return output;
}
function accepted(input) {
  try { decodeAuthorityRequestFrame(input); return true; }
  catch { return false; }
}
test('native Rust matches canonical TypeScript C4d request admission exactly', (t) => {
  assert.ok(existsSync(executable), 'native test-only probe must be built by pinned Cargo');
  const cases = [];
  const add = (label, bytes) => cases.push({ label, bytes });
  const baseline = encodeAuthorityRequestFrame(base());
  add('baseline', baseline);
  for (const path of ['ok', '科研/archivo', 'emoji/😀', 'a'.repeat(255),
    'a/'.repeat(63) + 'z', 'a/b/c', 'AUXIL', 'com0', 'file.name']) {
    add('valid path ' + path.slice(0, 25), encodeAuthorityRequestFrame({ ...base(), relativePath: path }));
  }
  for (const path of ['', '..', '.', 'a/../b', 'a//b', 'a\\b', 'C:/root',
    'CON', 'con.txt', 'PRN', 'AUX', 'NUL', 'COM1', 'COM¹.log',
    'CONIN$', 'CONOUT$.txt', 'a/CONIN$',
    'LPT²', 'LPT³.txt', 'a:', 'a?', 'a*', 'a|b', 'trailing.',
    'trailing ', 'a/'.repeat(65) + 'z', 'a'.repeat(256), 'a'.repeat(4097)]) {
    add('invalid path ' + path.slice(0, 25), frame(JSON.stringify({ ...base(), relativePath: path })));
  }
  for (const [key, value] of [
    ['version', 2], ['version', 1.5], ['requestId', 'BAD'],
    ['requestId', '11111111-1111-5111-8111-111111111111'],
    ['requestId', '11111111-1111-4111-7111-111111111111'],
    ['rootRef', 'ABCDEF0123456789ABCDEF0123456789'],
    ['rootRef', 'C:/outside'], ['expectedEpoch', '0'],
    ['expectedEpoch', '01'], ['expectedEpoch', '18446744073709551616'],
    ['kind', 'authorize-path']]) {
    add('invalid field ' + key + ' ' + value, frame(JSON.stringify({ ...base(), [key]: value })));
  }
  const json = JSON.stringify(base());
  for (const [label, raw] of [
    ['whitespace', ' ' + json], ['newline', json + '\n'],
    ['version decimal', json.replace('"version":1', '"version":1.0')],
    ['duplicate key', json.replace('"version":1', '"version":1,"version":1')],
    ['unknown key', json.replace('"kind"', '"other":0,"kind"')],
    ['escaped member', json.replace('"kind"', '"\\u006bind"')],
    ['reordered fields', JSON.stringify({ relativePath: base().relativePath, ...base() })],
    ['BOM', '\ufeff' + json], ['array', '[]'],
  ]) add(label, frame(raw));
  add('invalid UTF8', frame(Buffer.from([0xc3, 0x28])));
  add('empty', Buffer.alloc(0));
  add('short header', Buffer.from([0, 0, 0]));
  add('trailing', Buffer.concat([baseline, Buffer.from([0])]));
  add('two frames', Buffer.concat([baseline, baseline]));
  for (const count of [0, 1, 8193, 0xffffffff]) {
    const broken = Buffer.from(baseline);
    broken.writeUInt32BE(count, 0);
    add('wrong header ' + count, broken);
  }
  const input = cases.map(c => c.bytes.toString('hex')).join('\n') + '\n';
  const result = spawnSync(executable, [], {
    cwd: root, input, encoding: 'utf8', timeout: 15000,
    maxBuffer: 1024 * 1024, windowsHide: true,
  });
  assert.equal(result.status, 0, 'native data-only probe did not complete');
  assert.equal(result.stderr, '', 'native probe emitted an error');
  const observed = result.stdout.trimEnd().split('\n');
  assert.equal(observed.length, cases.length, 'native probe changed message cardinality');
  const expected = cases.map(c => accepted(c.bytes) ? 'accept' : 'deny');
  const admitted = expected.filter(value => value === 'accept').length;
  const rejected = expected.length - admitted;
  assert.ok(admitted >= 10 && rejected >= 50, 'do not silently reduce either admission corpus');
  for (let i = 0; i < cases.length; i++) {
    assert.equal(observed[i], expected[i], 'cross-runtime divergence: ' + cases[i].label);
  }
  t.diagnostic(`${cases.length} exact frames: ${admitted} accepted, ${rejected} rejected by both implementations`);
});
