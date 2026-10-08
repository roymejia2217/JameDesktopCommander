import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ReadProcessOutputArgsSchema } from '../dist/tools/schemas.js';
import { startProcess, readProcessOutput } from '../dist/tools/improved-process-tools.js';

function getPid(result) {
  const text = result.content?.[0]?.text ?? '';
  const match = text.match(/Process started with PID (\d+)/);
  assert.ok(match, 'start_process must return a PID');
  return Number(match[1]);
}

test('wait_for exit accepts a negative offset for a bounded terminal tail', async () => {
  const parsed = ReadProcessOutputArgsSchema.safeParse({
    pid: 123,
    wait_for: 'exit',
    offset: -8,
    length: 8,
  });
  assert.equal(parsed.success, true, 'a bounded tail must be allowed with exit waiting');
});

test('wait_for exit continues to reject absolute positive offsets', () => {
  const parsed = ReadProcessOutputArgsSchema.safeParse({
    pid: 123,
    wait_for: 'exit',
    offset: 9,
    length: 8,
  });
  assert.equal(parsed.success, false);
});

test('one exit wait returns last lines and completion status without a second read', async () => {
  const started = await startProcess({
    command: `node -e "setTimeout(() => { for(let i=0;i<65;i++) console.log('slice-' + i); }, 500)"`,
    timeout_ms: 100,
  });
  const pid = getPid(started);
  const result = await readProcessOutput({
    pid,
    timeout_ms: 10_000,
    wait_for: 'exit',
    offset: -5,
    length: 5,
  });
  const text = result.content?.[0]?.text ?? '';
  assert.ok(!result.isError, text);
  assert.match(text, /Reading last 5 lines/);
  assert.match(text, /slice-64/);
  assert.doesNotMatch(text, /slice-0(?:\D|$)/);
  assert.match(text, /Process completed with exit code 0/);
});

test('tail exit wait respects the deadline and does not cancel its process', async () => {
  const started = await startProcess({
    command: `node -e "setTimeout(() => console.log('FINAL-TAIL'), 1200)"`,
    timeout_ms: 100,
  });
  const pid = getPid(started);
  const pending = await readProcessOutput({
    pid, wait_for: 'exit', offset: -3, length: 3, timeout_ms: 100,
  });
  assert.match(pending.content?.[0]?.text ?? '', /exit wait deadline reached/);
  const completed = await readProcessOutput({
    pid, wait_for: 'exit', offset: -3, length: 3, timeout_ms: 10_000,
  });
  const text = completed.content?.[0]?.text ?? '';
  assert.ok(!completed.isError, text);
  assert.match(text, /FINAL-TAIL/);
  assert.match(text, /Process completed with exit code 0/);
});
