import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  confirmedSingleResultUpdate,
  definitelyRejectedResultBytes,
  RemoteResultUnconfirmedError,
} from '../dist/remote-device/remote-result-confirmation.js';
import { RemoteChannel } from '../dist/remote-device/remote-channel.js';
import { MCPDevice } from '../dist/remote-device/device.js';

process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';

const ID = 'local-test-call-001';

/** State-bearing fake of UPDATE...WHERE id/status...RETURNING id. */
function makeStorage({ initialStatus = 'executing', responses = [],
  expiresAtMs = Date.now() + 60000 } = {}) {
  const state = { id: ID, status: initialStatus, result: null };
  const writes = [];
  const queue = [...responses];
  const client = {
    from(table) {
      assert.equal(table, 'mcp_remote_calls');
      return {
        update(data) {
          const filters = {};
          const builder = {
            eq(key, value) { filters[key] = value; return builder; },
            gt(key, value) { filters[key + '_min'] = Date.parse(value); return builder; },
            async select(field) {
              assert.equal(field, 'id,status');
              const scripted = queue.shift();
              if (scripted === 'lost-ack') {
                if (filters.id === state.id && filters.status === state.status &&
                  Number.isFinite(filters.timeout_at_min) && expiresAtMs > filters.timeout_at_min) {
                  state.status = data.status;
                  state.result = data.result ?? null;
                }
                writes.push({ data, filters, outcome: 'lost-ack' });
                return { data: null, error: { code: 'NETWORK', message: 'connection lost' } };
              }
              if (scripted === 'invalid-bytes') {
                writes.push({ data, filters, outcome: 'invalid-bytes' });
                return { data: null, error: { code: '22P05', message: 'cannot encode NUL' } };
              }
              if (scripted === 'write-error') {
                writes.push({ data, filters, outcome: 'write-error' });
                return { data: null, error: { code: 'UNKNOWN', message: 'failed' } };
              }
              const matched = filters.id === state.id && filters.status === state.status &&
                Number.isFinite(filters.timeout_at_min) && expiresAtMs > filters.timeout_at_min;
              if (matched) {
                state.status = data.status;
                state.result = data.result ?? null;
              }
              writes.push({ data, filters, outcome: matched ? 'committed' : 'zero-rows' });
              // Model a malformed provider ACK even though the write committed:
              // the caller must not falsely mark the result as published.
              if (matched && scripted === 'wrong-terminal-ack') {
                return { data: [{ id: state.id, status: 'executing' }], error: null };
              }
              return { data: matched ? [{ id: state.id, status: state.status }] : [], error: null };
            },
          };
          return builder;
        },
      };
    },
  };
  const channel = Object.create(RemoteChannel.prototype);
  channel.client = client;
  return { channel, state, writes };
}

test('requires exactly one returned matching ID, not a 204, zero rows or an unverified ACK', () => {
  confirmedSingleResultUpdate({ data: [{ id: ID, status: 'completed' }], error: null }, ID, 'completed');
  confirmedSingleResultUpdate({ data: [{ id: ID, status: 'failed' }], error: null }, ID, 'failed');
  for (const response of [
    { data: null, error: null }, { data: [], error: null },
    { data: [{ id: 'other' }], error: null },
    { data: [{ id: ID }, { id: ID }], error: null },
    { data: [{ id: ID, status: 'completed' }], error: { code: 'NETWORK' } },
    { data: [{ id: ID }], error: null },
    { data: [{ id: ID, status: 'executing' }], error: null },
    { data: [{ id: ID, status: 'failed' }], error: null },
    { data: [{ id: ID, status: null }], error: null },
  ]) assert.throws(() => confirmedSingleResultUpdate(response, ID, 'completed'),
    RemoteResultUnconfirmedError);
  assert.equal(definitelyRejectedResultBytes({ data: null, error: { code: '22P05' } }), true);
  assert.equal(definitelyRejectedResultBytes({ data: null, error: { code: 'NETWORK' } }), false);
});

test('confirmed terminal publication sanitizes bytes and cannot rewrite a terminal row', async () => {
  const { channel, state, writes } = makeStorage();
  const result = { content: [{ type: 'text', text: 'safe\u0000text' }] };
  assert.equal(await channel.updateCallResult(ID, 'completed', result), 'confirmed');
  assert.equal(state.status, 'completed');
  assert.equal(state.result.content[0].text, 'safetext');
  assert.equal(writes[0].filters.status, 'executing');
  await assert.rejects(channel.updateCallResult(ID, 'failed', null, 'late'), RemoteResultUnconfirmedError);
  assert.equal(state.status, 'completed', 'Late update must preserve terminal state');
});

test('wrong terminal status in a returned row is not a confirmed publication', async () => {
  const { channel, state, writes } = makeStorage({ responses: ['wrong-terminal-ack'] });
  await assert.rejects(channel.updateCallResult(ID, 'completed', { value: 'ok' }),
    RemoteResultUnconfirmedError);
  assert.equal(state.status, 'completed', 'Fake storage committed before malformed ACK');
  assert.equal(writes.length, 1, 'An unconfirmed publication must not be rewritten');
});

test('lost response after COMMIT is indeterminate and must never trigger a fallback', async () => {
  const { channel, state, writes } = makeStorage({ responses: ['lost-ack'] });
  await assert.rejects(channel.updateCallResult(ID, 'completed', { value: 'ok' }),
    RemoteResultUnconfirmedError);
  assert.equal(state.status, 'completed', 'Fake server committed before ACK was lost');
  assert.equal(writes.length, 1, 'No second write after ambiguous transport error');
});

test('deterministic 22P05 rejection permits only a confirmed terminal failure', async () => {
  const { channel, state, writes } = makeStorage({ responses: ['invalid-bytes'] });
  const outcome = await channel.updateCallResult(ID, 'completed', { contents: 'bad binary' });
  assert.equal(outcome, 'fallback_confirmed');
  assert.equal(state.status, 'failed');
  assert.equal(state.result, null);
  assert.equal(writes.length, 2);
  assert.equal(writes[1].data.error_message, 'MCP result could not be stored.');
  assert.equal(writes[1].filters.status, 'executing');
});

test('zero-row fallback and unknown errors fail closed', async () => {
  const noMatch = makeStorage({ initialStatus: 'failed', responses: ['invalid-bytes'] });
  await assert.rejects(noMatch.channel.updateCallResult(ID, 'completed', { x: 1 }),
    RemoteResultUnconfirmedError);
  assert.equal(noMatch.state.status, 'failed');
  const unknown = makeStorage({ responses: ['write-error'] });
  await assert.rejects(unknown.channel.updateCallResult(ID, 'completed', { x: 1 }),
    RemoteResultUnconfirmedError);
  assert.equal(unknown.writes.length, 1);
});

test('expired but still executing request cannot be completed or failed', async () => {
  const expired = makeStorage({ expiresAtMs: Date.now() - 60000 });
  await assert.rejects(expired.channel.updateCallResult(ID, 'completed', { x: 1 }),
    RemoteResultUnconfirmedError);
  assert.equal(expired.state.status, 'executing');
  assert.equal(expired.writes[0].outcome, 'zero-rows');
  const expiredFallback = makeStorage({ expiresAtMs: Date.now() - 60000,
    responses: ['invalid-bytes'] });
  await assert.rejects(expiredFallback.channel.updateCallResult(ID, 'completed', { x: 1 }),
    RemoteResultUnconfirmedError);
  assert.equal(expiredFallback.state.status, 'executing');
  assert.equal(expiredFallback.writes.length, 2);
});

test('concurrent terminal writes cannot both be acknowledged', async () => {
  const { channel, state } = makeStorage();
  const values = await Promise.allSettled([
    channel.updateCallResult(ID, 'completed', { x: 1 }),
    channel.updateCallResult(ID, 'failed', null, 'failure'),
  ]);
  assert.equal(values.filter(value => value.status === 'fulfilled').length, 1);
  assert.equal(values.filter(value => value.status === 'rejected').length, 1);
  assert.ok(['completed', 'failed'].includes(state.status));
});

async function withDeviceCapture(publication, action) {
  const device = new MCPDevice();
  const seen = [];
  const writes = [];
  device.deviceId = 'test-device';
  device.desktop = { callClientTool: async () => ({ content: [{ type: 'text', text: 'ok' }] }) };
  device.remoteChannel = {
    markCallExecuting: async () => true,
    updateCallResult: async (...args) => {
      writes.push(args[1]);
      if (publication instanceof Error) throw publication;
      return publication;
    },
  };
  const originalInfo = console.info, originalError = console.error;
  try {
    console.info = msg => { if (typeof msg === 'string' && msg.startsWith('[JDC remote call]')) seen.push(msg); };
    console.error = msg => { if (typeof msg === 'string' && msg.startsWith('[JDC remote call]')) seen.push(msg); };
    await device.handleNewToolCall({
      new: { id: ID, tool_name: 'synthetic-read-only', tool_args: {}, device_id: 'test-device' },
    });
    action(seen, writes);
  } finally {
    console.info = originalInfo;
    console.error = originalError;
  }
}

test('device emits published receipt only for an explicitly confirmed result', async () => {
  await withDeviceCapture('confirmed', (logs, writes) => {
    assert.ok(logs.some(l => l.includes('stage=result_published')));
    assert.deepEqual(writes, ['completed']);
  });
  await withDeviceCapture('fallback_confirmed', (logs, writes) => {
    assert.ok(logs.some(l => l.includes('stage=failure_published')));
    assert.ok(!logs.some(l => l.includes('stage=result_published')));
    assert.deepEqual(writes, ['completed']);
  });
});

test('device refuses fake success and never rewrites an ambiguous completed result as failed', async () => {
  for (const response of [undefined, new RemoteResultUnconfirmedError()]) {
    await withDeviceCapture(response, (logs, writes) => {
      assert.ok(logs.some(l => l.includes('stage=local_completed')));
      assert.ok(logs.some(l => l.includes('stage=result_publish_failed')));
      assert.ok(!logs.some(l => l.includes('stage=result_published')));
      assert.ok(!logs.some(l => l.includes('stage=execution_failed')));
      assert.deepEqual(writes, ['completed']);
    });
  }
});
