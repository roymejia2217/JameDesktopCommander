import assert from 'node:assert/strict';
import { test } from 'node:test';
import { executeTunnelProbe } from '../dist/tools/tunnel-probe.js';

const nonceA = '0123456789abcdef0123456789abcdef';
const nonceB = 'abcdef0123456789abcdef0123456789';
const runtimeBuild = { schemaVersion: 1, kind: 'git', packageVersion: '0.2.52',
  sourceCommit: 'a'.repeat(40), workspaceClean: true };

test('fresh requests echo an exact nonce and retain an instance-scoped identifier', async () => {
  const now = () => new Date('2026-10-15T12:34:56.000Z');
  const a = await executeTunnelProbe({ challenge: nonceA }, async () => runtimeBuild, now);
  const b = await executeTunnelProbe({ challenge: nonceB }, async () => runtimeBuild, now);
  assert.equal(a.isError, undefined);
  assert.equal(a.structuredContent.kind, 'mcp_tool_round_trip_only');
  assert.equal(a.structuredContent.challenge, nonceA);
  assert.equal(b.structuredContent.challenge, nonceB);
  assert.equal(a.structuredContent.runtimeInstanceId, b.structuredContent.runtimeInstanceId);
  assert.match(a.structuredContent.runtimeInstanceId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(a.structuredContent.observedAtUtc, '2026-10-15T12:34:56.000Z');
  assert.deepEqual(JSON.parse(a.content[0].text), a.structuredContent);
  assert.deepEqual(a.structuredContent.runtimeBuild, runtimeBuild);
});

test('rejects wrong length, upper-case, extra fields, and unsafe challenge values', async () => {
  let identityReads = 0;
  const reader = async () => { identityReads++; return runtimeBuild; };
  for (const bad of [
    undefined, null, {}, { challenge: 123 },
    { challenge: nonceA.toUpperCase() }, { challenge: nonceA.slice(1) },
    { challenge: nonceA + '00' }, { challenge: 'x'.repeat(32) },
    { challenge: nonceA, token: 'never echo' }, { challenge: nonceA, origin: 'ui' },
    { challenge: '<script>alert(1)</script>' },
  ]) {
    const result = await executeTunnelProbe(bad, reader);
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent, undefined);
    assert.equal(result.content[0].text, 'Invalid MCP probe challenge.');
    assert.doesNotMatch(JSON.stringify(result), /token|never echo|script/i);
  }
  assert.equal(identityReads, 0, 'Invalid inputs must not perform filesystem reads');
});

test('unavailable runtime provenance is explicit, not a false claimed revision', async () => {
  const result = await executeTunnelProbe({ challenge: nonceA },
    async () => ({ schemaVersion: 1, kind: 'unavailable' }));
  assert.equal(result.structuredContent.runtimeBuild.kind, 'unavailable');
  assert.ok(!('sourceCommit' in result.structuredContent.runtimeBuild));
  assert.doesNotMatch(JSON.stringify(result), /password|private.key|bearer/i);
});
