import assert from 'node:assert/strict';
import { test } from 'node:test';
import YAML from 'yaml';
import { planWindowsTunnelRuntimeProfileCutover } from '../dist/platform/windows/tunnel-cutover-preflight.js';

const original = String.raw`E:\Proyectos\JameDesktopCommander-runtime-cf47811\dist\index.js`;
const candidate = String.raw`E:\Proyectos\JameDesktopCommander-runtime-f7f7f4\dist\index.js`;
const options = { originalEntry: original, candidateEntry: candidate, allowedRoot: String.raw`E:\Proyectos` };

function fixture(command = '"C:\\Program Files\\nodejs\\node.exe" "' + original + '"') {
  return YAML.stringify({
    health: { url_file: 'C:/health-local-file', privateKeyRef: 'UNRELATED-DATA' },
    mcp: { commands: [{ channel: 'stdio', command }] },
  });
}

test('preflight proposes an exact one-field change without modifying other YAML', () => {
  const input = fixture();
  const result = planWindowsTunnelRuntimeProfileCutover(input, options);
  assert.equal(YAML.parse(result.stagedProfile).mcp.commands[0].command.includes(candidate), true);
  assert.equal(YAML.parse(result.stagedProfile).health.privateKeyRef, 'UNRELATED-DATA');
  assert.equal(input.includes(original), true);
  assert.notEqual(result.originalSha256, result.stagedSha256);
  assert.match(result.originalSha256, /^[0-9A-F]{64}$/i);
  assert.equal(result.profileChanges, 1);
});

test('preflight rejects ambiguous, absent and repeated references', () => {
  assert.throws(() => planWindowsTunnelRuntimeProfileCutover(fixture('echo safe'), options), /reference|unchanged/i);
  assert.throws(() => planWindowsTunnelRuntimeProfileCutover(fixture(original + ' ' + original), options), /exactly one|ambiguous/i);
  assert.throws(() => planWindowsTunnelRuntimeProfileCutover(YAML.stringify({ mcp: { commands: [{command: original}, {command: original}] } }), options), /exactly one/i);
});

test('preflight rejects boundary escapes and same-runtime replacements', () => {
  const input = fixture();
  assert.throws(() => planWindowsTunnelRuntimeProfileCutover(input, {...options, candidateEntry: 'C:\\Temp\\evil.js'}), /root|path|entry/i);
  assert.throws(() => planWindowsTunnelRuntimeProfileCutover(input, {...options, candidateEntry: original}), /same|identical/i);
  assert.throws(() => planWindowsTunnelRuntimeProfileCutover(input, {...options, candidateEntry: 'relative\\dist\\index.js'}), /absolute|path/i);
});

test('preflight refuses malformed or nonconforming profiles', () => {
  assert.throws(() => planWindowsTunnelRuntimeProfileCutover('mcp: [invalid', options));
  assert.throws(() => planWindowsTunnelRuntimeProfileCutover(YAML.stringify({mcp:{commands:'bad'}}),options));
  assert.throws(() => planWindowsTunnelRuntimeProfileCutover(YAML.stringify({mcp:{commands:[{channel:'stdio',command:original}], extra:original}}),options), /ambiguous|reference|outside/i);
});

test('preflight handles YAML double-quoted command backslash escapes', () => {
  const command = '"C:\\Program Files\\nodejs\\node.exe" "' + original + '"';
  const input = 'mcp:\n  commands:\n    - channel: stdio\n      command: ' + JSON.stringify(command) + '\n';
  const plan = planWindowsTunnelRuntimeProfileCutover(input, options);
  const parsed = YAML.parse(plan.stagedProfile);
  assert.equal(parsed.mcp.commands[0].command, command.replace(original, candidate));
  assert.equal(plan.profileChanges, 1);
});
