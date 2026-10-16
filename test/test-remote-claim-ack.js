import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RemoteChannel } from '../dist/remote-device/remote-channel.js';
import { MCPDevice } from '../dist/remote-device/device.js';

process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';
const ID = 'claim-test-id';
const DEVICE = 'test-device';

function channelWithClaim(response, { deviceId = DEVICE } = {}) {
  const channel = new RemoteChannel();
  channel.deviceId = deviceId;
  const filters = {};
  const builder = {
    eq(k, v) { filters[k] = v; return builder; },
    gt(k, v) { filters[k] = v; return builder; },
    select(k) { filters.selected = k; return Promise.resolve(
      typeof response === 'function' ? response(filters) : response); },
  };
  channel.client = { from(name) {
    assert.equal(name, 'mcp_remote_calls');
    return { update(patch) {
      assert.deepEqual(patch, { status: 'executing' });
      return builder;
    } };
  } };
  return { channel, filters };
}

const owned = { data: [{ id: ID, device_id: DEVICE }], error: null };

test('conditional DB claim requires ID, correct device, pending status and expiry', async () => {
  const { channel, filters } = channelWithClaim(owned);
  assert.equal(await channel.markCallExecuting(ID), true);
  assert.equal(filters.id, ID);
  assert.equal(filters.device_id, DEVICE);
  assert.equal(filters.status, 'pending');
  assert.equal(filters.selected, 'id,device_id');
  assert.ok(Number.isFinite(Date.parse(filters.timeout_at)), 'missing finite expiry filter');
});

test('incorrect, empty, extra, malformed and wrong-device responses fail closed', async () => {
  for (const response of [
    { data: null, error: null }, { data: [], error: null },
    { data: [{ id: ID, device_id: 'other-device' }], error: null },
    { data: [{ id: 'other-id', device_id: DEVICE }], error: null },
    { data: [{ id: ID, device_id: DEVICE }, { id: ID, device_id: DEVICE }], error: null },
    { data: [null], error: null },
  ]) {
    const { channel } = channelWithClaim(response);
    assert.equal(await channel.markCallExecuting(ID), false);
  }
});

test('DB rejection or unknown result cannot authorize execution', async () => {
  for (const response of [
    { data: null, error: { code: 'NETWORK', message: 'ack lost' } },
    { data: [{ id: ID, device_id: DEVICE }], error: { code: 'UNKNOWN' } },
  ]) {
    const { channel } = channelWithClaim(response);
    assert.equal(await channel.markCallExecuting(ID), false);
  }
  const { channel } = channelWithClaim(() => { throw new Error('network disconnected'); });
  assert.equal(await channel.markCallExecuting(ID), false);
  const unregistered = channelWithClaim(owned, { deviceId: null });
  assert.equal(await unregistered.channel.markCallExecuting(ID), false);
});

test('a post-commit lost acknowledgment remains unconfirmed; no fallback re-claim', async () => {
  let commits = 0;
  const { channel } = channelWithClaim(filters => {
    if (filters.id === ID) commits++;
    return { data: null, error: { code: 'NETWORK' } };
  });
  assert.equal(await channel.markCallExecuting(ID), false);
  assert.equal(commits, 1, 'an indeterminate claim must not be retried');
});

function makeExecutor(channel) {
  const device = new MCPDevice();
  device.deviceId = DEVICE;
  device.desktop = { callClientTool: async () => { channel.executions++; return { content: [] }; } };
  device.remoteChannel = {
    isVerifiedPreclaim: () => false,
    markCallExecuting: async id => {
      if (channel.row.id !== id || channel.row.status !== 'pending') return false;
      channel.row.status = 'executing';
      return true;
    },
    updateCallResult: async () => 'confirmed',
  };
  return device;
}

test('two independent device processes competing for one DB row execute once', async () => {
  const shared = { row: { id: ID, status: 'pending' }, executions: 0 };
  const a = makeExecutor(shared);
  const b = makeExecutor(shared);
  const request = { new: { id: ID, device_id: DEVICE, tool_name: 'example', tool_args: {} } };
  await Promise.all([a.handleNewToolCall(request), b.handleNewToolCall(request)]);
  assert.equal(shared.executions, 1, 'DB CAS must protect across separate in-memory caches');
});

test('lost-ack and forged claimed marker cannot execute or publish a result', async () => {
  const shared = { row: { id: ID, status: 'executing' }, executions: 0 };
  const device = makeExecutor(shared);
  await device.handleNewToolCall({
    claimed: true,
    new: { id: ID, device_id: DEVICE, tool_name: 'example', tool_args: {} },
  });
  assert.equal(shared.executions, 0);
});
