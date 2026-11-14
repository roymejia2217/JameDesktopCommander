import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { terminalManager } from '../dist/terminal-manager.js';

const shell = process.platform === 'win32' ? 'powershell.exe' : '/bin/sh';
const ownedPids = new Set();
const EVENT_DEADLINE_MS = 10_000;

function quoteShell(value) {
  return process.platform === 'win32'
    ? "'" + value.replaceAll("'", "''") + "'"
    : "'" + value.replaceAll("'", "'\"'\"'") + "'";
}

function interactiveCommand(executable) {
  const invocation = (process.platform === 'win32' ? '& ' : '')
    + quoteShell(executable) + ' -i';
  return process.platform === 'win32'
    ? invocation + '; exit $LASTEXITCODE'
    : invocation;
}

async function startInteractive(executable) {
  const result = await terminalManager.executeCommand(
    interactiveCommand(executable), 3_000, shell, true, {
      onStarted(pid) { ownedPids.add(pid); },
    },
  );
  assert.ok(result.pid > 0, 'a real interpreter shell process must start');
  assert.ok(terminalManager.getSession(result.pid),
    'the interpreter must still be interactive after startup');
  assert.ok(ownedPids.has(result.pid), 'owned child must be registered for cleanup');
  return result.pid;
}

async function observeEvaluation(pid, source, expected) {
  const before = terminalManager.captureOutputSnapshot(pid);
  assert.ok(before, 'REPL must expose an output snapshot');
  assert.equal(terminalManager.sendInputToProcess(pid, source), true,
    'the actual interpreter must accept stdin');
  const deadline = Date.now() + EVENT_DEADLINE_MS;
  while (true) {
    const output = terminalManager.getOutputSinceSnapshot(pid, before) ?? '';
    if (output.includes(expected)) return;
    const remaining = deadline - Date.now();
    assert.ok(remaining > 0,
      'REPL did not evaluate input before deadline: '
        + terminalManager.getOutputTail(pid, 2000));
    const snapshot = terminalManager.captureOutputSnapshot(pid);
    assert.ok(snapshot, 'the session must exist while awaiting evaluation');
    const change = await terminalManager.waitForSessionChange(pid, snapshot, remaining);
    assert.equal(change, 'output',
      'REPL evaluation did not produce expected output; event=' + change
        + '; tail=' + terminalManager.getOutputTail(pid, 2000));
  }
}

async function stopOwned(pid) {
  if (!(pid > 0) || !ownedPids.has(pid)) return;
  if (terminalManager.getSession(pid)) {
    assert.equal(terminalManager.forceTerminate(pid), true,
      'owned REPL process tree must terminate');
    assert.equal(await terminalManager.waitForSessionExit(pid, 7_000), 'exit',
      'owned REPL must exit without leaving child sessions');
  }
  assert.equal(terminalManager.getSession(pid), undefined,
    'no active REPL session may survive cleanup');
  ownedPids.delete(pid);
}

after(async () => {
  for (const pid of [...ownedPids]) await stopOwned(pid);
  assert.equal(ownedPids.size, 0, 'all owned REPL processes must be closed');
});

test('Node REPL computes a deterministic value from stdin', { timeout: 20_000 }, async () => {
  let pid;
  try {
    pid = await startInteractive(process.execPath);
    await observeEvaluation(pid,
      "console.log(['JDC','NODE','REPL','PROOF'].join('_'), 6 * 7)",
      'JDC_NODE_REPL_PROOF 42');
  } finally {
    if (pid) await stopOwned(pid);
  }
});

test('Node REPL accepts sequential input without losing output', { timeout: 20_000 }, async () => {
  let pid;
  try {
    pid = await startInteractive(process.execPath);
    await observeEvaluation(pid,
      "console.log(['JDC','NODE','FIRST'].join('_'), 8 * 5)",
      'JDC_NODE_FIRST 40');
    await observeEvaluation(pid,
      "console.log(['JDC','NODE','SECOND'].join('_'), 8 * 6)",
      'JDC_NODE_SECOND 48');
  } finally {
    if (pid) await stopOwned(pid);
  }
});

test('Python REPL evaluates stdin when interpreter is installed',
  { timeout: 20_000 }, async (t) => {
    const candidates = process.platform === 'win32' ? ['python', 'python3'] : ['python3', 'python'];
    let python = null;
    for (const name of candidates) {
      const probe = spawnSync(name, ['--version'], {
        encoding: 'utf8', timeout: 5_000, windowsHide: true,
      });
      if (probe.status === 0 && /Python 3\./.test(
        (probe.stdout ?? '') + (probe.stderr ?? '')
      )) {
        python = name;
        break;
      }
    }
    if (!python) {
      t.skip('No usable Python 3 interpreter is installed on this host');
      return;
    }
    let pid;
    try {
      pid = await startInteractive(python);
      await observeEvaluation(pid,
        "print('_'.join(('JDC','PYTHON','REPL','PROOF')), 6 * 7)",
        'JDC_PYTHON_REPL_PROOF 42');
    } finally {
      if (pid) await stopOwned(pid);
    }
  });

test('Node REPL propagates nonzero exit and rejects further stdin',
  { timeout: 20_000 }, async () => {
    let pid;
    try {
      pid = await startInteractive(process.execPath);
      assert.equal(terminalManager.sendInputToProcess(pid, 'process.exit(7)'), true);
      assert.equal(await terminalManager.waitForSessionExit(pid, 10_000), 'exit');
      const result = terminalManager.readOutputPaginated(pid, -40, 40);
      assert.ok(result, 'completed session must remain queryable');
      assert.equal(result.isComplete, true);
      assert.equal(result.exitCode, 7, 'actual nonzero child exit must be propagated');
      assert.equal(terminalManager.sendInputToProcess(pid, 'console.log(0)'), false,
        'a completed REPL must reject further stdin');
    } finally {
      if (pid) await stopOwned(pid);
    }
  });