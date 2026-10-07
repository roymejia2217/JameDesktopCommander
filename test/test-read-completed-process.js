import assert from 'assert';
import { startProcess, readProcessOutput } from '../dist/tools/improved-process-tools.js';

function extractPid(startResult) {
  const text = startResult.content?.[0]?.text ?? '';
  const pidMatch = text.match(/Process started with PID (\d+)/);
  assert(pidMatch, 'Should get PID from start_process');
  return Number(pidMatch[1]);
}

function resultText(result) {
  return result.content?.map((item) => item.text ?? '').join('\n') ?? '';
}

async function readUntilCompleted(pid, expectedOutput) {
  const firstRead = await readProcessOutput({
    pid,
    timeout_ms: 5_000,
    offset: 0,
  });

  assert(!firstRead.isError, 'Should read process output without error');
  assert(
    resultText(firstRead).includes(expectedOutput),
    `Should contain expected output: ${expectedOutput}`,
  );

  const firstText = resultText(firstRead);
  if (firstText.includes('Process completed with exit code')) {
    return firstRead;
  }

  const completionRead = await readProcessOutput({
    pid,
    timeout_ms: 5_000,
    offset: 0,
  });

  assert(!completionRead.isError, 'Should observe process completion without error');
  assert(
    resultText(completionRead).includes('Process completed with exit code 0'),
    'Should observe successful process completion',
  );
  return completionRead;
}

async function assertCompletedOutputRemainsReadable(pid, expectedOutput) {
  const completedRead = await readProcessOutput({
    pid,
    timeout_ms: 1_000,
    offset: 0,
  });

  assert(!completedRead.isError, 'Should be able to read from completed process');
  const text = resultText(completedRead);
  assert(
    text.includes(expectedOutput),
    'Completed session must retain the final process output',
  );
  assert(
    text.includes('Process completed with exit code 0'),
    'Completed session must retain completion metadata',
  );
}

async function testReadCompletedProcessOutput() {
  console.log('Testing read_process_output on completed process...');

  const startResult = await startProcess({
    command: 'node -e "setTimeout(() => console.log(\'SUCCESS MESSAGE\'), 1000)"',
    timeout_ms: 500,
  });
  const pid = extractPid(startResult);

  await readUntilCompleted(pid, 'SUCCESS MESSAGE');
  await assertCompletedOutputRemainsReadable(pid, 'SUCCESS MESSAGE');

  console.log('PASS delayed process output remains readable after completion');
}

async function testImmediateCompletion() {
  console.log('Testing immediate completion...');

  const startResult = await startProcess({
    command: 'node -e "console.log(\'IMMEDIATE OUTPUT\')"',
    timeout_ms: 2_000,
  });
  const pid = extractPid(startResult);

  await readUntilCompleted(pid, 'IMMEDIATE OUTPUT');
  await assertCompletedOutputRemainsReadable(pid, 'IMMEDIATE OUTPUT');

  console.log('PASS immediate process output remains readable after completion');
}

async function runTests() {
  try {
    await testReadCompletedProcessOutput();
    await testImmediateCompletion();
    console.log('\nAll completed-process output tests passed.');
    return true;
  } catch (error) {
    console.error('\nCompleted-process output test failed:', error.message);
    if (error instanceof Error && error.stack) {
      console.error(error.stack);
    }
    return false;
  }
}

runTests()
  .then((success) => {
    process.exit(success ? 0 : 1);
  })
  .catch((error) => {
    console.error('Test error:', error);
    process.exit(1);
  });
