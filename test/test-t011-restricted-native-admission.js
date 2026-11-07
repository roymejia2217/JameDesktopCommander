import assert from 'node:assert/strict';
import { test } from 'node:test';
import { link, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

// No installed JDC configuration is accessed by this test.
const testConfig = resolve(
  process.env.DESKTOP_COMMANDER_TEST_CONFIG_ROOT || '.tmp/test-config',
  String(process.pid),
);
assert.equal(
  process.env.DESKTOP_COMMANDER_CONFIG_DIR &&
    resolve(process.env.DESKTOP_COMMANDER_CONFIG_DIR),
  testConfig,
  'E_TEST_ISOLATION_REQUIRED: use the repository test config preloader',
);

const { configManager } = await import('../dist/config-manager.js');
const {
  validatePath, readFileInternal, readFileFromDisk, readMultipleFiles,
  writeFile: jdcWrite, writePdf, createDirectory, listDirectory, moveFile, getFileInfo,
} = await import('../dist/tools/filesystem.js');
const { searchManager } = await import('../dist/search-manager.js');

async function withFixture(policy, run) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-t011-native-required-'));
  const allowed = join(root, 'allowed');
  const inside = join(allowed, 'inside.txt');
  const outside = join(root, 'outside-sentinel.txt');
  const alias = join(allowed, 'alias.txt');
  await mkdir(allowed);
  await writeFile(inside, 'INSIDE_OK\n');
  await writeFile(outside, 'OUTSIDE_UNCHANGED\n');
  await link(outside, alias);
  const a = await stat(alias);
  const b = await stat(outside);
  assert.equal(a.dev, b.dev, 'positive control: actual same-volume hardlink');
  assert.equal(a.ino, b.ino, 'positive control: the SAME native object');
  assert.ok(a.nlink >= 2, 'hardlink attack setup must be real');

  const previous = configManager.getAllowedDirectoriesForFilesystem;
  configManager.getAllowedDirectoriesForFilesystem = async () =>
    typeof policy === 'function' ? policy(allowed) : policy;
  let operationError;
  let integrityError;
  try {
    try {
      await run({ root, allowed, inside, outside, alias });
    } catch (error) {
      operationError = error;
    }
    // Preserve the outside-byte verdict EVEN WHEN an assertion above fails.
    try {
      assert.equal(await readFile(outside, 'utf8'), 'OUTSIDE_UNCHANGED\n');
    } catch (error) {
      integrityError = error;
    }
  } finally {
    if (previous === undefined) delete configManager.getAllowedDirectoriesForFilesystem;
    else configManager.getAllowedDirectoriesForFilesystem = previous;
    await rm(root, { recursive: true, force: true });
  }
  if (operationError && integrityError) {
    throw new AggregateError([operationError, integrityError],
      'Both the restricted operation and outside-sentinel integrity failed');
  }
  if (integrityError) throw integrityError;
  if (operationError) throw operationError;
}

const denied = /E_CAPABILITY_UNAVAILABLE/;

test('T011 P0: a configured root cannot read an external file through a real hardlink', async () => {
  await withFixture(allowed => [allowed], async ({ alias }) => {
    await assert.rejects(readFileInternal(alias, 0, Number.MAX_SAFE_INTEGER), denied);
    await assert.rejects(readFileFromDisk(alias), denied);
  });
});

test('T011 P0: restricted policy denies pathname I/O before any side effect', async () => {
  await withFixture(allowed => [allowed], async ({ allowed, inside, alias }) => {
    const newDir = join(allowed, 'created');
    const renamed = join(allowed, 'renamed.txt');
    await assert.rejects(validatePath(inside), denied);
    await assert.rejects(jdcWrite(alias, 'CORRUPTION', 'rewrite'), denied);
    await assert.rejects(jdcWrite(inside, 'CORRUPTION', 'append'), denied);
    await assert.rejects(writePdf(join(allowed, 'create.pdf'), '# Unsafe'), denied);
    const multiple = await readMultipleFiles([alias]);
    assert.equal(multiple.length, 1);
    assert.equal(multiple[0].content, undefined);
    assert.match(multiple[0].error, denied);
    await assert.rejects(createDirectory(newDir), denied);
    await assert.rejects(listDirectory(allowed), denied);
    await assert.rejects(moveFile(inside, renamed), denied);
    await assert.rejects(getFileInfo(alias), denied);
    await assert.rejects(
      searchManager.startSearch({
        rootPath: allowed, pattern: 'INSIDE_OK', searchType: 'content',
      }), denied,
    );
    await assert.rejects(stat(newDir), { code: 'ENOENT' });
    await assert.rejects(stat(renamed), { code: 'ENOENT' });
    assert.equal(await readFile(inside, 'utf8'), 'INSIDE_OK\n');
  });
});

test('T011 P0: explicit unrestricted [] preserves local read/write', async () => {
  await withFixture([], async ({ inside }) => {
    assert.equal(await readFileInternal(inside, 0, Number.MAX_SAFE_INTEGER), 'INSIDE_OK\n');
    await jdcWrite(inside, 'UPDATED\n', 'rewrite');
    assert.equal(await readFile(inside, 'utf8'), 'UPDATED\n');
  });
});

test('T011 P0: malformed persisted policy never becomes unrestricted', async () => {
  for (const corrupt of ['[]', null, ['']]) {
    await withFixture(corrupt, async ({ inside }) => {
      await assert.rejects(validatePath(inside),
        /E_CAPABILITY_UNAVAILABLE|Filesystem access denied/);
    });
  }
});

test('T011 P0: the real JDC MCP stdio server denies restricted external hardlinks', {
  timeout: 30_000,
}, async () => {
  await withFixture([], async ({ root, allowed, alias }) => {
    const instance = new Client({ name: 'jdc-t011-native-required-test', version: '1.0.0' });
    const inherited = {};
    for (const name of [
      'PATH', 'HOME', 'USERPROFILE', 'SystemRoot', 'APPDATA', 'LOCALAPPDATA',
      'TEMP', 'TMP', 'HOMEDRIVE', 'HOMEPATH',
    ]) {
      if (typeof process.env[name] === 'string') inherited[name] = process.env[name];
    }
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [resolve('dist/index.js')],
      cwd: process.cwd(),
      env: {
        ...inherited,
        DESKTOP_COMMANDER_CONFIG_DIR: join(root, 'isolated-mcp-config'),
      },
    });
    try {
      await instance.connect(transport);
      const configuration = await instance.callTool({
        name: 'set_config_value',
        arguments: { key: 'allowedDirectories', value: [allowed], origin: 'llm' },
      });
      assert.notEqual(configuration.isError, true,
        'set_config_value must persist a real restricted policy on the child MCP process');

      async function mustDeny(name, args) {
        const response = await instance.callTool({ name, arguments: args });
        const text = response.content?.filter(x => x.type === 'text')
          .map(x => x.text).join('\n') ?? '';
        assert.equal(response.isError, true, name + ' must deny restricted pathname access');
        assert.match(text, denied, name + ' must identify native capability unavailability');
        assert.doesNotMatch(text, /OUTSIDE_UNCHANGED/,
          name + ' must not disclose the external file bytes');
      }
      await mustDeny('read_file', { path: alias });
      await mustDeny('write_file', { path: alias, content: 'CORRUPTION', mode: 'rewrite' });
      await mustDeny('render_workspace', { path: alias });
    } finally {
      await instance.close();
    }
  });
});