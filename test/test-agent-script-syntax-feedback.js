import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { checkScriptSyntax, withScriptSyntaxFeedback } from '../dist/utils/script-syntax-diagnostics.js';

test('agent receives a failed syntax diagnostic without executing JavaScript or losing the write result', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-agent-syntax-'));
  try {
    const target = path.join(dir, 'invalid.js');
    const marker = path.join(dir, 'should-not-exist');
    await fs.writeFile(target, `await ( ;\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed');`);
    const result = await withScriptSyntaxFeedback({ content: [{ type: 'text', text: 'Successfully wrote file' }] }, target);
    assert.equal(result.isError, undefined, 'The saved file is not a failed write');
    assert.equal(result.content[0].text, 'Successfully wrote file');
    assert.match(result.content[1].text, /syntax|lint/i);
    assert.match(result.content[1].text, /FAIL/i);
    assert.equal(result.structuredContent?.scriptValidation?.status, 'failed');
    await assert.rejects(fs.stat(marker), { code: 'ENOENT' });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
test('valid JavaScript returns PASSED without being executed; non-scripts remain unchanged', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-agent-syntax-'));
  try {
    const marker = path.join(dir, 'must-not-exist');
    const target = path.join(dir, 'valid.cjs');
    await fs.writeFile(target, `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed');`);
    const valid = await checkScriptSyntax(target);
    assert.equal(valid.status, 'passed');
    await assert.rejects(fs.stat(marker), { code: 'ENOENT' });
    const original = { content: [{ type: 'text', text: 'Saved' }] };
    const unchanged = await withScriptSyntaxFeedback(original, path.join(dir, 'note.txt'));
    assert.deepEqual(unchanged, original);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('PowerShell parser rejects bad syntax without evaluating code', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-agent-syntax-'));
  try {
    const target = path.join(dir, "agent's invalid.ps1");
    await fs.writeFile(target, 'if ($true { Write-Output 1 }');
    const actual = await checkScriptSyntax(target);
    assert.ok(['failed', 'unavailable'].includes(actual.status));
    if (process.platform === 'win32') assert.equal(actual.status, 'failed');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
test('Python syntax is parsed but never executed, with explicit unavailability if missing', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-agent-python-'));
  try {
    const marker = path.join(dir, 'executed');
    const target = path.join(dir, 'agent.py');
    await fs.writeFile(target, `open(${JSON.stringify(marker)}, 'w').write('executed')\nprint('missing'\n`);
    const bad = await checkScriptSyntax(target);
    assert.ok(['failed', 'unavailable'].includes(bad.status));
    await fs.writeFile(target, `open(${JSON.stringify(marker)}, 'w').write('executed')\n`);
    const valid = await checkScriptSyntax(target);
    assert.ok(['passed', 'unavailable'].includes(valid.status));
    await assert.rejects(fs.stat(marker), { code: 'ENOENT' });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
test('Bash syntax validation never executes an agent script or startup injection', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-agent-bash-'));
  const previousBashEnv = process.env.BASH_ENV;
  try {
    const marker = path.join(dir, 'executed');
    const preload = path.join(dir, 'preload.sh');
    await fs.writeFile(preload, `echo malicious > ${JSON.stringify(marker)}\n`);
    process.env.BASH_ENV = preload;
    const target = path.join(dir, 'agent.sh');
    await fs.writeFile(target, 'if then\necho should-not-run\n');
    const invalid = await checkScriptSyntax(target);
    assert.ok(['failed', 'unavailable'].includes(invalid.status));
    await fs.writeFile(target, `echo valid > ${JSON.stringify(marker)}\n`);
    const valid = await checkScriptSyntax(target);
    assert.ok(['passed', 'unavailable'].includes(valid.status));
    await assert.rejects(fs.stat(marker), { code: 'ENOENT' });
  } finally {
    if (previousBashEnv === undefined) delete process.env.BASH_ENV;
    else process.env.BASH_ENV = previousBashEnv;
    await fs.rm(dir, { recursive: true, force: true });
  }
});
test('TypeScript without a trusted runtime compiler is explicitly unavailable, not falsely PASSED', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-agent-ts-'));
  try {
    const target = path.join(dir, 'agent.ts');
    await fs.writeFile(target, 'const item: number = 1;');
    const report = await checkScriptSyntax(target);
    assert.equal(report.status, 'unavailable');
    assert.match(report.diagnostics.join(' '), /TypeScript/);
    const annotated = await withScriptSyntaxFeedback({ content: [{ type: 'text', text: 'Saved' }] }, target);
    assert.equal(annotated.structuredContent?.scriptValidation?.status, 'unavailable');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
test('PowerShell linter reports warnings only when the standard analyzer is available', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-agent-ps-lint-'));
  try {
    const target = path.join(dir, 'agent.ps1');
    const marker = path.join(dir, 'never-run');
    await fs.writeFile(target, `Write-Host 'hello'; [System.IO.File]::WriteAllText('${marker}', 'executed')\n`);
    const report = await checkScriptSyntax(target);
    assert.ok(['passed', 'failed', 'unavailable'].includes(report.status));
    if (report.lint?.status === 'failed') {
      assert.equal(report.status, 'failed');
      assert.match(report.diagnostics.join(' '), /PSAvoidUsingWriteHost/i);
    }
    if (report.lint?.status === 'unavailable') assert.equal(report.scope, 'syntax');
    await assert.rejects(fs.stat(marker), { code: 'ENOENT' });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
test('ShellCheck missing is explicit; syntax PASS never pretends lint PASS', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-agent-shellcheck-'));
  try {
    const target = path.join(dir, 'agent.sh');
    await fs.writeFile(target, '#!/usr/bin/env bash\nvalue=one\necho $value\n');
    const report = await checkScriptSyntax(target);
    if (report.status === 'unavailable') return; // Bash parser absent.
    assert.ok(report.lint, 'ShellCheck status must be represented separately from Bash syntax');
    if (report.lint.status === 'unavailable') {
      assert.equal(report.status, 'passed');
      assert.equal(report.scope, 'syntax');
      assert.match(report.diagnostics.join(' '), /ShellCheck.*not available/i);
    } else if (report.lint.status === 'failed') {
      assert.equal(report.status, 'failed');
      assert.match(report.diagnostics.join(' '), /SC[0-9]+/);
    }
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
test('node syntax checker strips startup preload options from the child environment', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-node-env-'));
  const previous = process.env.NODE_OPTIONS;
  try {
    const marker = path.join(dir, 'preload-executed');
    const preload = path.join(dir, 'preload.cjs');
    const source = path.join(dir, 'valid.cjs');
    await fs.writeFile(preload, `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed');`);
    await fs.writeFile(source, 'const number = 1;');
    process.env.NODE_OPTIONS = `--require=${preload}`;
    const report = await checkScriptSyntax(source);
    assert.equal(report.status, 'passed');
    await assert.rejects(fs.stat(marker), { code: 'ENOENT' });
  } finally {
    if (previous === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = previous;
    await fs.rm(dir, { recursive: true, force: true });
  }
});
test('overlarge scripts report an incomplete check without launching a parser', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-syntax-limit-'));
  try {
    const target = path.join(dir, 'large.js');
    await fs.writeFile(target, Buffer.alloc(1024 * 1024 + 1, 'a'));
    const result = await checkScriptSyntax(target);
    assert.equal(result.status, 'unavailable');
    assert.match(result.diagnostics.join(' '), /1 MiB/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
