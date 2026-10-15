import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  parseTunnelFunctionalHealth,
  readTunnelFunctionalDiagnostics,
} from '../dist/platform/windows/tunnel-functional-diagnostics.js';

const example = {
  live: true, ready: true, components: {
    mcp: { details: {
      initialize: { ok: true },
      tools_list: { ok: false, complete: false, tool_names: ['SECRET_TOOL'] },
    } },
    dispatcher: { details: { active: 1, failures: 9, timeouts: 9 } },
    queue: { details: { depth: 0 } },
    'control-plane': { details: { consecutive_failures: 0 } },
  },
};
test('observational-only result distinguishes readiness from MCP discovery', () => {
  assert.deepEqual(parseTunnelFunctionalHealth(example), {
    kind: 'observational_only',
    localHealth: 'ready',
    mcpInitializeObserved: true,
    toolDiscovery: 'observed_incomplete',
    dispatcher: { active: 1, failuresCumulative: 9, timeoutsCumulative: 9 },
    queueDepth: 0, controlPlaneFailuresConsecutive: 0,
  });
  assert.doesNotMatch(JSON.stringify(parseTunnelFunctionalHealth(example)), /SECRET_TOOL/);
});
test('incomplete snapshots are unknown rather than an invented healthy status', () => {
  const partial = structuredClone(example);
  delete partial.components.mcp.details.tools_list;
  delete partial.components.dispatcher.details.timeouts;
  const found = parseTunnelFunctionalHealth(partial);
  assert.equal(found.toolDiscovery, 'unverified');
  assert.equal(found.dispatcher.timeoutsCumulative, null);
  assert.throws(() => parseTunnelFunctionalHealth({ live: true, ready: true }), /components/);
});
test('missing readiness never becomes true by default', () => {
  const partial = structuredClone(example);
  delete partial.live;
  assert.equal(parseTunnelFunctionalHealth(partial).localHealth, 'not_ready');
});
test('only exact HTTP loopback URLs are accepted', async () => {
  let invoked = 0;
  const mock = async () => { invoked++; return Response.json(example); };
  for (const bad of [
    'https://127.0.0.1:1234/', 'http://localhost:1234/',
    'http://10.0.0.2:1234/', 'http://evil.example:1234/',
    'http://127.0.0.1:1234/x', 'http://127.0.0.1:1234/?token=x',
    'http://admin:secret@127.0.0.1:1234/', 'file:///c:/temp',
  ]) {
    await assert.rejects(readTunnelFunctionalDiagnostics(bad, mock));
  }
  assert.equal(invoked, 0);
});
test('official request has bounded deadline, GET and redirect rejection', async () => {
  let invoked = 0;
  const mock = async (url, init) => {
    invoked++;
    assert.equal(url.toString(), 'http://127.0.0.1:1234/health?details=true');
    assert.equal(init.method, 'GET');
    assert.equal(init.redirect, 'error');
    assert.equal(init.cache, 'no-store');
    assert.ok(init.signal instanceof AbortSignal);
    return Response.json(example);
  };
  const found = await readTunnelFunctionalDiagnostics('http://127.0.0.1:1234/', mock);
  assert.equal(invoked, 1);
  assert.equal(found.dispatcher.timeoutsCumulative, 9);
});
test('HTTP errors, missing body and oversized responses fail closed', async () => {
  for (const response of [
    new Response(null, { status: 401 }),
    new Response(null, { status: 200 }),
    new Response('x'.repeat(262145), { status: 200 }),
    new Response('bad json', { status: 200 }),
  ]) {
    await assert.rejects(readTunnelFunctionalDiagnostics('http://127.0.0.1:1234/',
      async () => response));
  }
});
test('counters are strictly nonnegative safe integers', () => {
  const bad = structuredClone(example);
  bad.components.dispatcher.details.timeouts = -1;
  bad.components.dispatcher.details.failures = 1.5;
  const v = parseTunnelFunctionalHealth(bad);
  assert.equal(v.dispatcher.timeoutsCumulative, null);
  assert.equal(v.dispatcher.failuresCumulative, null);
});
