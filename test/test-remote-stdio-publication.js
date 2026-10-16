import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { MCPDevice } from '../dist/remote-device/device.js';
import { RemoteChannel } from '../dist/remote-device/remote-channel.js';
import { DesktopCommanderIntegration } from '../dist/remote-device/desktop-commander-integration.js';

process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';
const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(here, 'fixtures', 'dying-mcp-server.js');
const deviceId = 'isolated-device';
const deadline = Date.now() + 60_000;

class FixtureIntegration extends DesktopCommanderIntegration {
  async resolveMcpConfig() {
    return { command: process.execPath, args: [fixture], cwd: here };
  }
}

function modeledPostgrest() {
  const rows = new Map();
  const writes = [];
  const client = {
    from(table) {
      assert.equal(table, 'mcp_remote_calls');
      return {
        update(patch) {
          const eq = new Map();
          let minimumDeadline = 0;
          const statement = {
            eq(key, value) { eq.set(key, value); return statement; },
            gt(key, value) {
              assert.equal(key, 'timeout_at');
              minimumDeadline = Date.parse(value);
              return statement;
            },
            async select(projection) {
              const row = rows.get(eq.get('id'));
              const accepted = row &&
                row.status === eq.get('status') &&
                row.device_id === (eq.get('device_id') ?? deviceId) &&
                row.timeout_at > minimumDeadline;
              if (!accepted) return { data: [], error: null };
              row.status = patch.status;
              if (Object.hasOwn(patch, 'result')) row.result = patch.result;
              writes.push({ id: row.id, status: patch.status });
              if (projection === 'id,device_id') {
                return { data: [{ id: row.id, device_id: row.device_id }], error: null };
              }
              assert.equal(projection, 'id,status');
              return { data: [{
                id: row.id,
                status: row.malformedTerminalAck ? 'executing' : row.status,
              }], error: null };
            },
          };
          return statement;
        },
      };
    },
  };
  return {
    rows, writes, client,
    add(id, malformedTerminalAck = false) {
      const row = {
        id, device_id: deviceId, timeout_at: deadline,
        status: 'pending', result: null, malformedTerminalAck,
      };
      rows.set(id, row);
      return row;
    },
  };
}

function collectReceipts() {
  const stages = [];
  const info = console.info;
  const error = console.error;
  function capture(original) {
    return (...args) => {
      const record = String(args[0] ?? '');
      if (record.startsWith('[JDC remote call]')) {
        assert.doesNotMatch(record, /fixture-ok|tool_args|Bearer|device_id|password/i);
        const stage = record.match(/ stage=([a-z_]+) /)?.[1];
        assert.ok(stage, 'receipt must include a bounded stage');
        stages.push(stage);
      } else original(...args);
    };
  }
  console.info = capture(info);
  console.error = capture(error);
  return { stages, restore: () => { console.info = info; console.error = error; } };
}
test('real MCP stdio child crosses remote claim, local result and terminal ACK', async () => {
  const desktop = new FixtureIntegration();
  const store = modeledPostgrest();
  const channel = new RemoteChannel();
  channel.client = store.client;
  channel.deviceId = deviceId;
  const device = new MCPDevice();
  device.deviceId = deviceId;
  device.remoteChannel = channel;
  device.desktop = desktop;
  const capture = collectReceipts();
  try {
    await desktop.initialize();
    async function deliver(id, toolName, badAck = false) {
      const row = store.add(id, badAck);
      const beforeWrites = store.writes.length;
      const beforeStages = capture.stages.length;
      await device.handleNewToolCall({ new: {
        id, device_id: deviceId, tool_name: toolName, tool_args: {},
      } });
      return { row, writes: store.writes.slice(beforeWrites),
        stages: capture.stages.slice(beforeStages) };
    }

    const good = await deliver('local-call-success', 'healthy-tool');
    assert.equal(good.row.status, 'completed');
    assert.match(JSON.stringify(good.row.result), /fixture-ok/);
    assert.deepEqual(good.writes.map(w => w.status), ['executing', 'completed']);
    assert.deepEqual(good.stages,
      ['received', 'claimed', 'local_completed', 'result_published']);

    const contradictory = await deliver('local-call-ambiguous', 'healthy-tool', true);
    assert.equal(contradictory.row.status, 'completed',
      'modeled DB committed before returning wrong terminal status');
    assert.deepEqual(contradictory.writes.map(w => w.status),
      ['executing', 'completed'], 'never issue a corrective second write');
    assert.deepEqual(contradictory.stages,
      ['received', 'claimed', 'local_completed', 'result_publish_failed']);

    const crashed = await deliver('local-call-crashed', 'crash-mid-call');
    assert.equal(crashed.row.status, 'failed');
    assert.deepEqual(crashed.writes.map(w => w.status), ['executing', 'failed']);
    assert.deepEqual(crashed.stages,
      ['received', 'claimed', 'execution_failed', 'failure_published']);
  } finally {
    capture.restore();
    await desktop.shutdown().catch(() => {});
  }
});
