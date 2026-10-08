#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  configManager,
  normalizeMaxProcessWaitMs,
} from '../dist/config-manager.js';
import {
  resolveProcessWaitMs,
  terminalManager,
} from '../dist/terminal-manager.js';
import {
  interactWithProcess,
  readProcessOutput,
} from '../dist/tools/improved-process-tools.js';
import { setConfigValue } from '../dist/tools/config.js';

const shell = process.platform === 'win32' ? 'powershell.exe' : '/bin/sh';
const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-process-events-'));
const DEFAULT_WAIT_CAP_MS = 180_000;

function shellQuote(value) {
  return process.platform === 'win32'
    ? `'${value.replaceAll("'", "''")}'`
    : `'${value.replaceAll("'", "'\"'\"'")}'`;
}

async function writeFixture(name, source) {
  const filePath = path.join(tempRoot, `${name}.cjs`);
  await fs.writeFile(filePath, source, 'utf8');
  return filePath;
}

function nodeCommand(scriptPath, args = []) {
  const parts = [process.execPath, scriptPath, ...args].map(shellQuote);
  return process.platform === 'win32'
    ? `& ${parts.join(' ')}`
    : parts.join(' ');
}

function textOf(result) {
  return result.content
    ?.filter((item) => item.type === 'text')
    .map((item) => item.text)
    .join('\n') ?? '';
}

function terminate(pid) {
  if (Number.isInteger(pid) && pid > 0) {
    try {
      terminalManager.forceTerminate(pid);
    } catch {
      // Best-effort test cleanup.
    }
  }
}

async function withIntervalForbidden(operation) {
  const originalSetInterval = globalThis.setInterval;
  let intervalCalls = 0;
  globalThis.setInterval = (...args) => {
    intervalCalls += 1;
    throw new Error(
      `Process reconciliation must be event-driven; setInterval was called with ${String(args[1])}ms`,
    );
  };

  try {
    const result = await operation();
    assert.equal(intervalCalls, 0, 'process reconciliation must not schedule polling intervals');
    return result;
  } finally {
    globalThis.setInterval = originalSetInterval;
  }
}

test('default process wait cap stays below the four-minute client ceiling', async () => {
  const config = await configManager.resetConfig();
  assert.equal(config.maxProcessWaitMs, DEFAULT_WAIT_CAP_MS);
  assert.ok(
    config.maxProcessWaitMs < 240_000,
    'default maxProcessWaitMs must stay below the known ~4 minute client ceiling',
  );
});

test('process wait limits fail closed when configuration is invalid or excessive', async () => {
  assert.equal(normalizeMaxProcessWaitMs(undefined), DEFAULT_WAIT_CAP_MS);
  assert.equal(normalizeMaxProcessWaitMs(-1), DEFAULT_WAIT_CAP_MS);
  assert.equal(normalizeMaxProcessWaitMs(300_000), DEFAULT_WAIT_CAP_MS);
  assert.equal(normalizeMaxProcessWaitMs(1_200), 1_200);
  assert.equal(resolveProcessWaitMs(300_000, 300_000), DEFAULT_WAIT_CAP_MS);
  assert.equal(resolveProcessWaitMs(5_000, 1_200), 1_200);

  await configManager.resetConfig();
  await configManager.setValue('maxProcessWaitMs', 300_000);
  const effectiveConfig = await configManager.getConfig();
  assert.equal(
    effectiveConfig.maxProcessWaitMs,
    DEFAULT_WAIT_CAP_MS,
    'direct or manually edited unsafe config must not expand the blocking wait ceiling',
  );
  await configManager.resetConfig();
});

test('set_config_value enforces the safe process wait ceiling', async () => {
  await configManager.resetConfig();

  const accepted = await setConfigValue({
    key: 'maxProcessWaitMs',
    value: '1200',
  });
  assert.notEqual(accepted.isError, true);
  assert.equal((await configManager.getConfig()).maxProcessWaitMs, 1_200);

  const rejected = await setConfigValue({
    key: 'maxProcessWaitMs',
    value: DEFAULT_WAIT_CAP_MS + 1,
  });
  assert.equal(rejected.isError, true);
  assert.match(textOf(rejected), /no greater than 180000ms/i);
  assert.equal(
    (await configManager.getConfig()).maxProcessWaitMs,
    1_200,
    'rejecting an unsafe wait limit must leave the previous safe value intact',
  );

  const nonPositive = await setConfigValue({
    key: 'maxProcessWaitMs',
    value: 0,
  });
  assert.equal(nonPositive.isError, true);
  assert.equal((await configManager.getConfig()).maxProcessWaitMs, 1_200);

  await configManager.resetConfig();
});

test('start_process reconciliation is event-driven and returns on process output/exit', async () => {
  await configManager.resetConfig();
  const fixture = await writeFixture(
    'start-event-driven',
    "setTimeout(() => console.log('event-driven-ok'), 80);",
  );

  let pid = -1;
  try {
    const result = await withIntervalForbidden(async () => {
      const value = await terminalManager.executeCommand(
        nodeCommand(fixture),
        5_000,
        shell,
        true,
      );
      pid = value.pid;
      return value;
    });

    assert.ok(pid > 0, 'a real child process must be started');
    assert.match(result.output, /event-driven-ok/);
    assert.equal(result.isBlocked, false);
    assert.equal(result.timingInfo?.exitReason, 'process_exit');
  } finally {
    terminate(pid);
  }
});

test('percentage progress does not look like an interactive prompt', async () => {
  await configManager.resetConfig();
  const fixture = await writeFixture(
    'percentage-progress',
    "process.stderr.write('Updating files:  42% (166/394)\\r'); setTimeout(() => process.exit(0), 180);",
  );

  let pid = -1;
  try {
    const result = await terminalManager.executeCommand(
      nodeCommand(fixture),
      2_000,
      shell,
      true,
    );
    pid = result.pid;

    assert.ok(pid > 0);
    assert.equal(result.isBlocked, false);
    assert.equal(result.timingInfo?.exitReason, 'process_exit');
    assert.match(result.output, /Updating files:\s+42% \(166\/394\)/);
  } finally {
    terminate(pid);
  }
});

test('start_process drains cross-stream startup output before returning on a prompt', async () => {
  await configManager.resetConfig();
  const fixture = await writeFixture(
    'startup-cross-stream-prompt',
    "process.stderr.write('>>> '); setTimeout(() => process.stdout.write('startup-cross-stream-output\\n'), 40); setTimeout(() => {}, 2_000);",
  );

  let pid = -1;
  try {
    const result = await withIntervalForbidden(async () => {
      const value = await terminalManager.executeCommand(
        nodeCommand(fixture),
        2_000,
        shell,
        false,
      );
      pid = value.pid;
      return value;
    });

    assert.ok(pid > 0);
    assert.equal(result.isBlocked, true);
    assert.match(
      result.output,
      /startup-cross-stream-output/,
      'start_process must drain late output from the other stdio stream before prompt handoff',
    );
  } finally {
    terminate(pid);
  }
});

test('read_process_output waits on terminal events without polling', async () => {
  await configManager.resetConfig();
  const fixture = await writeFixture(
    'read-event-driven',
    "setTimeout(() => console.log('later-output'), 180); setTimeout(() => {}, 350);",
  );

  const start = await terminalManager.executeCommand(
    nodeCommand(fixture),
    30,
    shell,
    false,
  );
  assert.ok(start.pid > 0);

  try {
    const result = await withIntervalForbidden(() =>
      readProcessOutput({
        pid: start.pid,
        timeout_ms: 2_000,
        offset: 0,
        length: 20,
      }),
    );

    assert.match(textOf(result), /later-output/);
  } finally {
    terminate(start.pid);
  }
});

test('read_process_output rejects exit waiting with positive absolute offsets', async () => {
  const result = await readProcessOutput({
    pid: 12345,
    timeout_ms: 1_000,
    offset: 20,
    length: 20,
    wait_for: 'exit',
  });

  assert.equal(result.isError, true);
  assert.match(
    textOf(result),
    /wait_for.*exit.*offset.*0/i,
    'exit waiting must fail closed with positive absolute offsets',
  );
});

test('read_process_output can wait for exit without returning on intermediate output', async () => {
  await configManager.resetConfig();
  const fixture = await writeFixture(
    'read-wait-for-exit',
    "setTimeout(() => console.log('workflow-progress-one'), 120); setTimeout(() => console.log('workflow-progress-two'), 240); setTimeout(() => process.exit(0), 420);",
  );

  const start = await terminalManager.executeCommand(
    nodeCommand(fixture),
    30,
    shell,
    false,
  );
  assert.ok(start.pid > 0);

  try {
    const result = await withIntervalForbidden(() =>
      readProcessOutput({
        pid: start.pid,
        timeout_ms: 2_000,
        offset: 0,
        length: 20,
        wait_for: 'exit',
      }),
    );

    const text = textOf(result);
    assert.match(text, /workflow-progress-one/);
    assert.match(text, /workflow-progress-two/);
    assert.match(
      text,
      /Process completed with exit code 0/,
      'exit mode must remain blocked across output events until the process completes',
    );
  } finally {
    terminate(start.pid);
  }
});

test('read_process_output exit mode returns on its bounded deadline without killing the process', async () => {
  await configManager.resetConfig();
  const fixture = await writeFixture(
    'read-wait-for-exit-deadline',
    "setTimeout(() => console.log('deadline-progress-one'), 60); setTimeout(() => console.log('deadline-progress-two'), 120); setTimeout(() => {}, 1_500);",
  );

  const start = await terminalManager.executeCommand(
    nodeCommand(fixture),
    25,
    shell,
    false,
  );
  assert.ok(start.pid > 0);

  try {
    const result = await withIntervalForbidden(() =>
      readProcessOutput({
        pid: start.pid,
        timeout_ms: 240,
        offset: 0,
        length: 20,
        wait_for: 'exit',
      }),
    );

    const text = textOf(result);
    assert.match(text, /deadline-progress-one/);
    assert.match(text, /exit wait deadline reached/);
    assert.doesNotMatch(text, /Process completed with exit code/);
    assert.ok(
      terminalManager.getSession(start.pid),
      'reaching the exit-wait deadline must not terminate the underlying process',
    );
  } finally {
    terminate(start.pid);
  }
});

test('read_process_output returns appends to an already-read partial line', async () => {
  await configManager.resetConfig();
  const fixture = await writeFixture(
    'partial-line-output',
    "process.stdout.write('phase-one'); setTimeout(() => process.stdout.write('-phase-two'), 220); setTimeout(() => {}, 1_000);",
  );

  const start = await terminalManager.executeCommand(
    nodeCommand(fixture),
    80,
    shell,
    false,
  );
  assert.ok(start.pid > 0);

  try {
    const firstRead = await readProcessOutput({
      pid: start.pid,
      timeout_ms: 120,
      offset: 0,
      length: 20,
    });
    assert.match(textOf(firstRead), /phase-one/);

    const secondRead = await readProcessOutput({
      pid: start.pid,
      timeout_ms: 600,
      offset: 0,
      length: 20,
    });
    assert.match(
      textOf(secondRead),
      /phase-two/,
      'a later append to the same unterminated line must be delivered exactly as new output',
    );
  } finally {
    terminate(start.pid);
  }
});

test('interact_with_process waits on terminal events without polling', async () => {
  await configManager.resetConfig();
  const start = await terminalManager.executeCommand('node -i', 3_000, shell, false);
  assert.ok(start.pid > 0);

  try {
    const result = await withIntervalForbidden(() =>
      interactWithProcess({
        pid: start.pid,
        input: "var __until=Date.now()+120; while(Date.now()<__until){}; console.log('interaction-ok')",
        timeout_ms: 2_000,
        wait_for_prompt: true,
      }),
    );

    assert.match(textOf(result), /interaction-ok/);
  } finally {
    terminate(start.pid);
  }
});

test('interact_with_process drains cross-stream output before returning on a prompt', async () => {
  await configManager.resetConfig();
  const fixture = await writeFixture(
    'cross-stream-prompt',
    "process.stdin.setEncoding('utf8'); process.stderr.write('>>> '); process.stdin.on('data', () => { process.stderr.write('>>> '); setTimeout(() => process.stdout.write('cross-stream-output\\n'), 40); });",
  );

  const start = await terminalManager.executeCommand(
    nodeCommand(fixture),
    1_000,
    shell,
    false,
  );
  assert.ok(start.pid > 0);

  try {
    const result = await withIntervalForbidden(() =>
      interactWithProcess({
        pid: start.pid,
        input: 'go',
        timeout_ms: 2_000,
        wait_for_prompt: true,
      }),
    );

    assert.match(
      textOf(result),
      /cross-stream-output/,
      'a prompt arriving on stderr must not hide stdout that follows in the same interaction',
    );
  } finally {
    terminate(start.pid);
  }
});

test('snapshot and state-change checks do not materialize the full retained output', async () => {
  await configManager.resetConfig();
  const fixture = await writeFixture(
    'bounded-state-inspection',
    "process.stdout.write('x'.repeat(20000) + 'TAIL_MARKER'); setTimeout(() => {}, 2_000);",
  );

  const started = await terminalManager.executeCommand(
    nodeCommand(fixture),
    25,
    shell,
    false,
  );
  assert.ok(started.pid > 0);

  const session = terminalManager.getSession(started.pid);
  assert.ok(session);

  let tail = terminalManager.getOutputTail(started.pid, 64);
  if (!/TAIL_MARKER$/.test(tail)) {
    const arrivalSnapshot = terminalManager.captureOutputSnapshot(started.pid);
    assert.ok(arrivalSnapshot);
    const arrival = await terminalManager.waitForSessionChange(
      started.pid,
      arrivalSnapshot,
      1_000,
    );
    assert.equal(arrival, 'output', 'fixture output must arrive before O(1) inspection assertions');
    tail = terminalManager.getOutputTail(started.pid, 64);
  }
  assert.match(tail, /TAIL_MARKER$/);

  const originalJoin = session.outputLines.join;
  session.outputLines.join = () => {
    throw new Error('full output materialization is forbidden for state inspection');
  };

  try {
    const snapshot = terminalManager.captureOutputSnapshot(started.pid);
    assert.ok(snapshot, 'snapshot capture must be O(1) over retained output');

    tail = terminalManager.getOutputTail(started.pid, 64);
    assert.ok(tail.length <= 64);
    assert.match(tail, /TAIL_MARKER$/);
  } finally {
    session.outputLines.join = originalJoin;
    terminate(started.pid);
  }

  const silentFixture = await writeFixture(
    'state-change-no-materialize',
    'setTimeout(() => {}, 2_000);',
  );
  const silent = await terminalManager.executeCommand(
    nodeCommand(silentFixture),
    25,
    shell,
    false,
  );
  assert.ok(silent.pid > 0);

  const snapshot = terminalManager.captureOutputSnapshot(silent.pid);
  assert.ok(snapshot);
  const originalGetOutputSinceSnapshot = terminalManager.getOutputSinceSnapshot;
  terminalManager.getOutputSinceSnapshot = () => {
    throw new Error('waitForSessionChange must not materialize process output');
  };

  try {
    const change = await terminalManager.waitForSessionChange(
      silent.pid,
      snapshot,
      80,
    );
    assert.equal(change, 'timeout');
  } finally {
    terminalManager.getOutputSinceSnapshot = originalGetOutputSinceSnapshot;
    terminate(silent.pid);
  }
});

test('an active session wins over stale completed state for a reused PID', async () => {
  await configManager.resetConfig();
  const fixture = await writeFixture(
    'pid-reuse-active-precedence',
    'setTimeout(() => {}, 2_000);',
  );

  const started = await terminalManager.executeCommand(
    nodeCommand(fixture),
    25,
    shell,
    false,
  );
  assert.ok(started.pid > 0);
  assert.ok(terminalManager.getSession(started.pid));

  const completedSessions = terminalManager.completedSessions;
  completedSessions.set(started.pid, {
    pid: started.pid,
    outputLines: ['stale-output-from-older-process'],
    exitCode: 0,
    startTime: new Date(Date.now() - 10_000),
    endTime: new Date(Date.now() - 9_000),
    evictedLines: 0,
    evictedChars: 0,
  });

  try {
    const snapshot = terminalManager.captureOutputSnapshot(started.pid);
    assert.ok(snapshot);
    const change = await terminalManager.waitForSessionChange(
      started.pid,
      snapshot,
      120,
    );
    assert.equal(
      change,
      'timeout',
      'stale completed state must never make a currently active reused PID look completed',
    );
  } finally {
    completedSessions.delete(started.pid);
    terminate(started.pid);
  }
});

test('rapid completed-process handoffs preserve every immediate output', async () => {
  await configManager.resetConfig();

  for (let index = 0; index < 12; index += 1) {
    const marker = `rapid-complete-${index}`;
    const fixture = await writeFixture(
      `rapid-complete-${index}`,
      `console.log(${JSON.stringify(marker)});`,
    );
    const started = await terminalManager.executeCommand(
      nodeCommand(fixture),
      2_000,
      shell,
      false,
    );

    assert.ok(started.pid > 0, `iteration ${index} should start a real process`);
    const completed = terminalManager.readOutputPaginated(started.pid, 0, 20);
    assert.ok(completed?.isComplete, `iteration ${index} should already be completed`);
    assert.match(
      completed.lines.join('\n'),
      new RegExp(marker),
      `iteration ${index} must retain its immediate stdout after completion`,
    );
  }
});

test('blocking process waits are capped without terminating the underlying process', async () => {
  await configManager.resetConfig();
  await configManager.setValue('maxProcessWaitMs', 150);
  assert.equal(
    (await configManager.getConfig()).maxProcessWaitMs,
    150,
    'the configured process wait cap must be observable before spawning the process',
  );

  const fixture = await writeFixture(
    'silent-long-running',
    'setTimeout(() => {}, 5_000);',
  );

  const startedAt = Date.now();
  const start = await terminalManager.executeCommand(
    nodeCommand(fixture),
    4_000,
    shell,
    true,
  );
  const startElapsed = Date.now() - startedAt;

  assert.ok(start.pid > 0);
  assert.equal(start.isBlocked, true);
  assert.ok(
    startElapsed < 1_500,
    `start_process should return near the configured cap, took ${startElapsed}ms`,
  );
  assert.ok(
    terminalManager.getSession(start.pid),
    'hitting the wait cap must hand off a still-running session rather than terminate it',
  );

  try {
    const readStartedAt = Date.now();
    const readResult = await readProcessOutput({
      pid: start.pid,
      timeout_ms: 4_000,
      offset: 0,
      length: 20,
    });
    const readElapsed = Date.now() - readStartedAt;

    assert.ok(
      readElapsed < 1_500,
      `read_process_output should honor maxProcessWaitMs, took ${readElapsed}ms`,
    );
    assert.match(textOf(readResult), /No output|still running|requested range/i);
  } finally {
    terminate(start.pid);
    await configManager.resetConfig();
  }
});

test('interact_with_process honors the same bounded wait contract', async () => {
  await configManager.resetConfig();
  const start = await terminalManager.executeCommand('node -i', 3_000, shell, false);
  assert.ok(start.pid > 0);

  await configManager.setValue('maxProcessWaitMs', 150);
  try {
    const startedAt = Date.now();
    const result = await interactWithProcess({
      pid: start.pid,
      input: 'var __until=Date.now()+1500; while(Date.now()<__until){}',
      timeout_ms: 4_000,
      wait_for_prompt: true,
    });
    const elapsed = Date.now() - startedAt;

    assert.ok(
      elapsed < 1_500,
      `interact_with_process should return near the configured cap, took ${elapsed}ms`,
    );
    assert.match(textOf(result), /timeout|incomplete|still running/i);
    assert.ok(
      terminalManager.getSession(start.pid),
      'hitting the interact wait cap must keep the REPL session alive',
    );
  } finally {
    terminate(start.pid);
    await configManager.resetConfig();
  }
});

test.after(async () => {
  await configManager.close();
  await fs.rm(tempRoot, { recursive: true, force: true });
});
