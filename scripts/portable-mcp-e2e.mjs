#!/usr/bin/env node
/**
 * Native CI check of a restored JDC portable candidate over real MCP stdio.
 * Never invokes tools, installs services, or uses host configuration.
 */
import assert from 'node:assert/strict';
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, parse, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const sourceRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const provided = process.argv[2];
assert.ok(provided && isAbsolute(provided), 'Expected absolute candidate directory');
const candidate = await realpath(provided);
const rel = relative(sourceRoot, candidate);
assert.ok(rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel),
  'Candidate must be outside the source checkout');

const manifest = JSON.parse(await readFile(join(candidate, 'candidate-manifest.json'), 'utf8'));
assert.equal(manifest.releaseEligible, false);
assert.equal(manifest.target, process.platform + '-' + process.arch);
const binary = join(candidate, manifest.runtimeExecutable);
const entrypoint = join(candidate, manifest.entrypoint);
for (const file of [binary, entrypoint]) {
  assert.ok((await lstat(file)).isFile(), 'Missing packaged runtime file');
}

const sdk = join(candidate, 'node_modules', '@modelcontextprotocol', 'sdk', 'dist', 'esm', 'client');
const [{ Client }, { StdioClientTransport }] = await Promise.all([
  import(pathToFileURL(join(sdk, 'index.js')).href),
  import(pathToFileURL(join(sdk, 'stdio.js')).href),
]);

const isolated = await mkdtemp(join(tmpdir(), 'jdc-portable-mcp-'));
const working = join(isolated, 'working');
await mkdir(working);
const fixture = join(working, 'portable-mcp-fixture.txt');
const original = 'jdc-portable-original\n';
const rewritten = 'jdc-portable-rewritten\n';
const appended = 'jdc-portable-appended\n';
await writeFile(fixture, original);
const env = {
  HOME: isolated, USERPROFILE: isolated, APPDATA: join(isolated, 'appdata'),
  LOCALAPPDATA: join(isolated, 'localappdata'), XDG_CONFIG_HOME: join(isolated, 'config'),
  XDG_CACHE_HOME: join(isolated, 'cache'), TEMP: isolated, TMP: isolated,
  DESKTOP_COMMANDER_CONFIG_DIR: join(isolated, 'jdc-config'),
  DESKTOP_COMMANDER_DISABLE_TELEMETRY: '1',
  PUPPETEER_SKIP_DOWNLOAD: '1',
  DC_FLAG_URL: 'http://127.0.0.1:9/',
  PATH: process.platform === 'win32'
    ? [join(process.env.SystemRoot || 'C:\\Windows', 'System32'),
      process.env.SystemRoot || 'C:\\Windows'].join(';')
    : '/usr/bin:/bin',
};
if (process.platform === 'win32') {
  env.SystemRoot = process.env.SystemRoot;
  env.windir = process.env.windir || process.env.SystemRoot;
  env.ComSpec = process.env.ComSpec;
  env.HOMEDRIVE = parse(isolated).root.slice(0, 2);
  env.HOMEPATH = isolated.slice(2);
}
const transport = new StdioClientTransport({
  command: binary, args: [entrypoint, '--no-onboarding'], cwd: working,
  env, stderr: 'ignore',
});
const client = new Client({ name: 'jdc-portable-acceptance', version: '1.0.0' },
  { capabilities: {} });
async function bounded(label, action) {
  let timer;
  try {
    return await Promise.race([
      action(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(label + ' deadline exceeded')), 30000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function callFixtureTool(name, args) {
  // SDK signature: callTool(params, resultSchema?, options?). Never pass
  // the timeout as the second argument (reserved for a Zod result schema).
  return client.callTool({ name, arguments: args }, undefined, { timeout: 20000 });
}
function toolText(result) {
  assert.ok(Array.isArray(result.content), 'MCP tool result must include content');
  return result.content.filter(item => item.type === 'text').map(item => item.text).join('\n');
}

try {
  await bounded('MCP initialize', () => client.connect(transport));
  assert.equal(client.getServerVersion()?.name, 'desktop-commander');
  const capabilities = client.getServerCapabilities();
  assert.ok(capabilities?.tools && capabilities?.resources && capabilities?.prompts,
    'Missing MCP capabilities');
  const tools = (await bounded('MCP tools/list', () => client.listTools())).tools;
  assert.ok(tools.length >= 20, 'Truncated MCP tool catalog');
  const names = tools.map(tool => tool.name);
  assert.equal(new Set(names).size, names.length, 'Duplicate MCP tool names');
  for (const required of ['read_file', 'list_directory', 'get_config', 'render_workspace']) {
    assert.ok(names.includes(required), 'Missing required tool: ' + required);
  }
  const resources = (await bounded('MCP resources/list', () => client.listResources())).resources;
  assert.ok(resources.length > 0, 'No MCP UI resources');
  const read = await bounded('MCP resources/read',
    () => client.readResource({ uri: resources[0].uri }));
  assert.ok(read.contents?.length > 0, 'MCP resource was empty');
  const prompts = (await bounded('MCP prompts/list', () => client.listPrompts())).prompts;
  assert.ok(Array.isArray(prompts), 'Invalid MCP prompts catalog');

  // T008: live tool calls are confined to disposable CI fixture paths.
  // Check on-disk bytes, not only the tool's success message.
  const listed = await callFixtureTool('list_directory', { path: working, depth: 1 });
  assert.notEqual(listed.isError, true, 'Fixture directory listing failed');
  assert.ok(toolText(listed).includes('portable-mcp-fixture.txt'), 'Fixture omitted from directory listing');

  const initialRead = await callFixtureTool('read_file', { path: fixture, offset: 0, length: 10 });
  assert.notEqual(initialRead.isError, true, 'Fixture read failed');
  assert.ok(toolText(initialRead).includes(original.trim()), 'Initial file contents differ');

  const rejected = await callFixtureTool('write_file', {
    path: fixture, content: 'unapproved-overwrite\n',
  });
  assert.equal(rejected.isError, true, 'Omitted mode must reject overwriting a nonempty file');
  assert.equal(await readFile(fixture, 'utf8'), original, 'Rejected write damaged original bytes');

  const rewrite = await callFixtureTool('write_file', {
    path: fixture, content: rewritten, mode: 'rewrite',
  });
  assert.notEqual(rewrite.isError, true, 'Explicit rewrite failed');
  assert.equal(await readFile(fixture, 'utf8'), rewritten, 'Rewrite result differs on disk');

  const append = await callFixtureTool('write_file', {
    path: fixture, content: appended, mode: 'append',
  });
  assert.notEqual(append.isError, true, 'Explicit append failed');
  assert.equal(await readFile(fixture, 'utf8'), rewritten + appended,
    'Append must preserve all existing bytes');

  const finalRead = await callFixtureTool('read_file', { path: fixture });
  assert.notEqual(finalRead.isError, true, 'Final fixture read failed');
  assert.ok(toolText(finalRead).includes(rewritten.trim()), 'Rewritten content missing from read result');
  assert.ok(toolText(finalRead).includes(appended.trim()), 'Appended content missing from read result');

  // T009: allowedDirectories is an application-level authorization policy.
  // All writes are restricted to disposable fixture paths, never host files.
  const allowedRoot = join(working, 'allowed');
  const deniedRoot = join(working, 'allowed-sibling');
  const allowedFile = join(allowedRoot, 'inside.txt');
  const deniedFile = join(deniedRoot, 'outside.txt');
  await mkdir(allowedRoot);
  await mkdir(deniedRoot);
  await writeFile(allowedFile, 'inside-initial\n');
  await writeFile(deniedFile, 'outside-initial\n');

  const configured = await callFixtureTool('set_config_value', {
    key: 'allowedDirectories', value: [allowedRoot],
  });
  assert.notEqual(configured.isError, true, 'Could not enable the restricted file policy');

  const allowedRead = await callFixtureTool('read_file', { path: allowedFile });
  assert.notEqual(allowedRead.isError, true, 'Policy denied an explicitly allowed file');
  const allowedWrite = await callFixtureTool('write_file', {
    path: allowedFile, content: 'inside-updated\n', mode: 'rewrite',
  });
  assert.notEqual(allowedWrite.isError, true, 'Policy denied an explicitly allowed write');
  assert.equal(await readFile(allowedFile, 'utf8'), 'inside-updated\n');

  async function assertDenied(name, args) {
    const result = await callFixtureTool(name, args);
    assert.equal(result.isError, true, 'Unauthorized MCP access succeeded: ' + name);
  }
  await assertDenied('read_file', { path: deniedFile });
  await assertDenied('write_file', {
    path: deniedFile, content: 'unauthorized\n', mode: 'rewrite',
  });
  const traversal = allowedRoot + sep + '..' + sep + 'allowed-sibling' + sep + 'outside.txt';
  await assertDenied('read_file', { path: traversal });

  const escapeLink = join(allowedRoot, 'escape');
  await symlink(deniedRoot, escapeLink, process.platform === 'win32' ? 'junction' : 'dir');
  await assertDenied('read_file', { path: join(escapeLink, 'outside.txt') });
  await assertDenied('write_file', {
    path: join(escapeLink, 'created-via-link.txt'), content: 'unauthorized\n', mode: 'rewrite',
  });
  await assert.rejects(lstat(join(deniedRoot, 'created-via-link.txt')), { code: 'ENOENT' });

  if (process.platform === 'linux') {
    const caseDifferentRoot = join(working, 'ALLOWED');
    await mkdir(caseDifferentRoot);
    assert.notEqual(await realpath(allowedRoot), await realpath(caseDifferentRoot),
      'Linux test filesystem must distinguish path case');
    const caseDifferentFile = join(caseDifferentRoot, 'case-outside.txt');
    await writeFile(caseDifferentFile, 'case-initial\n');
    await assertDenied('read_file', { path: caseDifferentFile });
    await assertDenied('write_file', {
      path: caseDifferentFile, content: 'unauthorized\n', mode: 'rewrite',
    });
    assert.equal(await readFile(caseDifferentFile, 'utf8'), 'case-initial\n',
      'Case-different unauthorized file was modified');
  }
  assert.equal(await readFile(deniedFile, 'utf8'), 'outside-initial\n',
    'Unauthorized file was modified');


  console.log(JSON.stringify({
    result: 'PASS', target: manifest.target, toolCount: tools.length,
    resourcesRead: read.contents.length, promptCount: prompts.length,
    isolatedWorkingDirectory: true, fileToolChecks: 6,
    modeOmissionRejected: true, accessPositiveChecks: 2,
    accessNegativeChecks: process.platform === 'linux' ? 7 : 5,
    outsideBytesPreserved: true, releaseEligible: false,
  }));
} finally {
  await client.close().catch(() => {});
  await rm(isolated, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
