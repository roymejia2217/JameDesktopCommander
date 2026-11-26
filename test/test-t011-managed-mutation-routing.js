import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createJdcServer } from '../dist/server.js';
import { toolHistory } from '../dist/utils/toolHistory.js';

test('real JDC SDK dispatches managed text writes and moves without legacy fallback', async () => {
  const calls = [];
  const marker = 'JDC_MANAGED_MUTATION_PRIVATE';
  const path = '/managed/report.txt';
  const server = createJdcServer({ managedMutation: async request => {
    calls.push(request);
    return { status: 'committed' };
  } });
  const sdk = new Client({ name: 'desktop-commander-app', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await sdk.connect(clientTransport);
    for (const [name, args] of [
      ['write_file', { path, content: marker }],
      ['write_file', { path, content: 'append', mode: 'append' }],
      ['move_file', { source: path, destination: '/managed/final.txt' }],
    ]) {
      const reply = await sdk.callTool({ name, arguments: args });
      assert.equal(reply.isError, false, JSON.stringify(reply));
      assert.equal(reply.content[0].text, 'NATIVE_MUTATION_COMMITTED');
    }
    assert.deepEqual(calls, [
      { kind: 'write', path, content: marker, mode: 'rewrite' },
      { kind: 'write', path, content: 'append', mode: 'append' },
      { kind: 'move', source: path, destination: '/managed/final.txt' },
    ]);
    for (const record of toolHistory.getRecentCalls({ maxResults: 3 })) {
      assert.ok(!JSON.stringify(record).includes(marker));
      assert.ok(!JSON.stringify(record).includes(path));
    }
    for (const [name, args] of [
      ['write_file', { path: '/outside.txt', content: 'x' }],
      ['write_file', { path: '/managed/../outside.txt', content: 'x' }],
      ['write_file', { path: '/managed/CON.txt', content: 'x' }],
      ['write_file', { path: '/managed/file.docx', content: 'x' }],
      ['write_file', { path, content: '\ud800' }],
      ['write_file', { path, content: 'x', rootRef: 'forged' }],
      ['write_file', { path, content: 'x', origin: 'ui' }],
      ['move_file', { source: path, destination: '/outside.txt' }],
      ['read_file', { path }],
      ['start_process', { command: 'echo forbidden' }],
    ]) {
      const reply = await sdk.callTool({ name, arguments: args, _meta: { 'jdc.nativeAuthorityRequired': false } });
      assert.equal(reply.isError, true, name);
    }
    assert.equal(calls.length, 3);
  } finally {
    await sdk.close();
    await server.close();
  }
});

test('mutation cancellation after submission never claims clean rejection', { timeout: 2000 }, async () => {
  const { handleManagedMutation } = await import('../dist/handlers/managed-mutation.js');
  const controller = new AbortController();
  let settle;
  const pending = new Promise(resolve => { settle = resolve; });
  try {
    const result = await handleManagedMutation((_request, signal) => {
      assert.equal(signal.aborted, false);
      controller.abort();
      return pending;
    }, 'write_file', { path: '/managed/a.txt', content: 'x' }, controller.signal);
    assert.equal(result.isError, true);
    assert.equal(result.content[0].text, 'E_NATIVE_MUTATION_OUTCOME_UNKNOWN');
  } finally {
    settle({ status: 'committed' });
  }
});

test('pre-submission cancellation, backend rejection and lost reply are distinct', async () => {
  const { handleManagedMutation } = await import('../dist/handlers/managed-mutation.js');
  const args = { path: '/managed/a.txt', content: 'x' };
  const controller = new AbortController();
  controller.abort();
  assert.equal((await handleManagedMutation(() => { throw Error('must not invoke'); }, 'write_file', args, controller.signal)).content[0].text, 'E_NATIVE_MUTATION_CANCELLED');
  for (const [op, code] of [
    [async () => ({ status: 'denied' }), 'E_NATIVE_MUTATION_DENIED'],
    [async () => ({ status: 'collision' }), 'E_NATIVE_MUTATION_COLLISION'],
    [async () => ({ status: 'recovery-required' }), 'E_NATIVE_MUTATION_OUTCOME_UNKNOWN'],
    [async () => { throw Error('private backend failure'); }, 'E_NATIVE_MUTATION_OUTCOME_UNKNOWN'],
  ]) {
    const result = await handleManagedMutation(op, 'write_file', args);
    assert.equal(result.isError, true);
    assert.equal(result.content[0].text, code);
  }
});


test('managed dispatcher serializes submissions and latches an unknown outcome', async () => {
  const { createManagedMutationDispatcher } = await import('../dist/handlers/managed-mutation.js');
  let complete;
  let invocations = 0;
  const dispatch = createManagedMutationDispatcher(async () => {
    invocations++;
    return new Promise(resolve => { complete = resolve; });
  });
  const args = { path: '/managed/a.txt', content: 'x' };
  const first = dispatch('write_file', args);
  await Promise.resolve();
  const busy = await dispatch('write_file', args);
  assert.equal(busy.isError, true);
  assert.equal(busy.content[0].text, 'E_NATIVE_MUTATION_BUSY');
  complete({ status: 'recovery-required' });
  assert.equal((await first).content[0].text, 'E_NATIVE_MUTATION_OUTCOME_UNKNOWN');
  const blocked = await dispatch('write_file', args);
  assert.equal(blocked.content[0].text, 'E_NATIVE_MUTATION_OUTCOME_UNKNOWN');
  assert.equal(invocations, 1);
});
