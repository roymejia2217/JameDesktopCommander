import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const testDir = path.join(root, 'test', 'integration', 'test_agent_script_syntax_feedback');
const configDir = path.join(root, '.tmp', 'integration-config', 'agent-script-syntax-feedback');
const call = (client, name, args) => client.callTool({
  name, arguments: args
}, undefined, { timeout: 30000 });

const transport = new StdioClientTransport({
  command: process.execPath, args: [path.join(root, 'dist/index.js'),
    '--config-dir', configDir, '--no-onboarding'],
  cwd: root, stderr: 'pipe',
  env: { ...process.env, DESKTOP_COMMANDER_DISABLE_TELEMETRY: 'true' },
});
const client = new Client({ name: 'agent-script-syntax-feedback-test', version: '1.0.0' },
  { capabilities: {} });
await fs.mkdir(testDir, { recursive: true });
await client.connect(transport, { timeout: 30000 });
const original = await call(client, 'get_config', {});
assert.equal(original.isError, undefined);
const previous = Object.fromEntries(original.structuredContent.entries
  .filter(entry => entry.editable).map(entry => [entry.key, entry.value]));
try {
  const allowed = await call(client, 'set_config_value', {
    key: 'allowedDirectories', value: [testDir], origin: 'llm'
  });
  assert.ok(!allowed.isError);
  const script = path.join(testDir, 'generated-agent.cjs');
  const marker = path.join(testDir, 'would-have-executed');
  const bad = await call(client, 'write_file', { path: script,
    content: 'const message = ;', mode: 'rewrite' });
  assert.ok(!bad.isError, 'write succeeded even if its script does not parse');
  assert.match(bad.content[0]?.text ?? '', /successfully wrote/i);
  assert.equal(bad.structuredContent?.scriptValidation?.status, 'failed');
  assert.equal(bad.structuredContent?.scriptValidation?.syntaxStatus, 'failed');
  assert.match(bad.content[1]?.text ?? '', /FAILED/i);
  const edited = await call(client, 'edit_block', { file_path: script,
    old_string: 'const message = ;',
    new_string: `const message = 'valid'; require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed');`,
    expected_replacements: 1 });
  assert.ok(!edited.isError);
  assert.equal(edited.structuredContent?.scriptValidation?.status, 'passed');
  assert.equal(edited.structuredContent?.scriptValidation?.syntaxStatus, 'passed');
  assert.match(edited.content.at(-1)?.text ?? '', /PASSED/i);
  await assert.rejects(fs.stat(marker), { code: 'ENOENT' });
  assert.match(await fs.readFile(script, 'utf8'), /message = 'valid'/);

  const appended = await call(client, 'write_file', {
    path: script, content: '\nconsole.log("appended");', mode: 'append'
  });
  assert.ok(!appended.isError);
  assert.equal(appended.structuredContent?.scriptValidation?.status, 'unavailable');
  assert.equal(appended.structuredContent?.scriptValidation?.syntaxStatus, 'unavailable');
  assert.match(appended.content.at(-1)?.text ?? '', /complete source snapshot unavailable/i);
  assert.match(await fs.readFile(script, 'utf8'), /appended/);
} finally {
  for (const [key, value] of Object.entries(previous)) {
    await call(client, 'set_config_value', { key, value, origin: 'llm' });
  }
  await fs.rm(testDir, { recursive: true, force: true });
  await client.close();
}
