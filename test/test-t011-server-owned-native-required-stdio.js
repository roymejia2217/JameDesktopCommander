// #139: genuine stdio server must fail closed when its process requires
// unavailable native authority, regardless of untrusted request _meta.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';

const SERVER = resolve('dist/index.js');
const IDENTITY = { name: 'desktop-commander-app', version: '1.0.0' };

async function connectIsolated(root, strict) {
  const sdk = new Client(IDENTITY, { capabilities: {} });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER, '--no-onboarding', ...(strict ? ['--require-native-authority'] : [])],
    cwd: root,
    env: {
      ...getDefaultEnvironment(),
      HOME: root, USERPROFILE: root,
      APPDATA: join(root, 'appdata'), LOCALAPPDATA: join(root, 'localappdata'),
      DESKTOP_COMMANDER_CONFIG_DIR: join(root, 'config'),
      DESKTOP_COMMANDER_DISABLE_TELEMETRY: '1',
      PUPPETEER_SKIP_DOWNLOAD: '1',
    },
    stderr: 'ignore',
  });
  await sdk.connect(transport);
  return sdk;
}

function reportedText(result) {
  return result.content?.filter(item => item.type === 'text')
    .map(item => item.text).join('\n') ?? '';
}

test('real JDC stdio process denies all tools when native authority is required but absent',
  { timeout: 90_000 }, async () => {
    const isolated = await mkdtemp(join(tmpdir(), 'jdc-native-required-'));
    let strict;
    let legacy;
    try {
      strict = await connectIsolated(isolated, true);
      const catalog = await strict.listTools();
      assert.ok(catalog.tools.some(tool => tool.name === 'read_file'));
      assert.ok(catalog.tools.some(tool => tool.name === 'start_process'));
      const attempted = [
        ['read_file', { path: join(isolated, 'inside.txt') }],
        ['read_multiple_files', { paths: [join(isolated, 'inside.txt')] }],
        ['start_process', { command: 'echo JDC_DENIAL_ONLY', timeout_ms: 1000 }],
        ['get_config', {}],
      ];
      for (const meta of [undefined, { 'jdc.nativeAuthorityRequired': false }]) {
        for (const [name, args] of attempted) {
          const result = await strict.callTool({ name, arguments: args, _meta: meta });
          assert.equal(result.isError, true, name + ' must be denied');
          assert.match(reportedText(result), /E_NATIVE_AUTHORITY_UNAVAILABLE/,
            name + ' must not invoke a legacy handler');
        }
      }
      const readable = join(isolated, 'inside.txt');
      const original = 'JDC_LEGACY_ALLOWED_EXACT\n';
      await writeFile(readable, original);
      legacy = await connectIsolated(isolated, false);
      const baseline = await legacy.callTool({ name: 'get_config', arguments: {} });
      assert.notEqual(baseline.isError, true,
        'legacy user-owned mode must remain available absent native enrollment');
      const settings = await legacy.callTool({
        name: 'set_config_value',
        arguments: { key: 'allowedDirectories', value: [isolated] },
      });
      assert.notEqual(settings.isError, true, reportedText(settings));
      const legacyRead = await legacy.callTool({
        name: 'read_file', arguments: { path: readable },
      });
      assert.notEqual(legacyRead.isError, true, reportedText(legacyRead));
      assert.ok(reportedText(legacyRead).includes(original.trim()),
        'legacy file bytes must remain accessible without protected enrollment');
    } finally {
      await legacy?.close();
      await strict?.close();
      await rm(isolated, { recursive: true, force: true });
    }
  });
