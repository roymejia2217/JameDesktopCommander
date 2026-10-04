// Test script to verify line counting accuracy in read_file.
import assert from 'assert';
import fs from 'fs/promises';
import os from 'os';
import { join } from 'path';

const originalHome = process.env.HOME;
const originalUserProfile = process.env.USERPROFILE;
const isolatedHome = await fs.mkdtemp(join(os.tmpdir(), 'dc-line-count-home-'));
const testDir = await fs.mkdtemp(join(os.tmpdir(), 'dc-line-count-files-'));

process.env.HOME = isolatedHome;
process.env.USERPROFILE = isolatedHome;

const [{ handleReadFile }, { configManager }] = await Promise.all([
  import('../dist/handlers/filesystem-handlers.js'),
  import('../dist/config-manager.js'),
]);

function extractTotalLines(result) {
  const text = result?.content?.[0]?.text ?? '';
  const match = text.match(/\(total: (\d+) lines/);
  return match ? Number.parseInt(match[1], 10) : null;
}

async function createTestFile(name, content) {
  const filePath = join(testDir, name);
  await fs.writeFile(filePath, content, 'utf8');
  return filePath;
}

async function testLineCount() {
  let passed = 0;
  let failed = 0;

  console.log('Testing line count accuracy in read_file...\n');

  const cases = [
    ['3 lines + trailing newline', 'trailing.txt', 'line1\nline2\nline3\n', 0, 2, 3],
    ['3 lines no trailing', 'no_trailing.txt', 'line1\nline2\nline3', 0, 2, 3],
    ['1 line + trailing newline', 'single_trailing.txt', 'hello\n', 0, 1000, 1],
    ['1 line no trailing', 'single_no_trailing.txt', 'hello', 0, 1000, 1],
    [
      '100-line partial read',
      'hundred.txt',
      Array.from({ length: 100 }, (_, i) => `Line ${i + 1}`).join('\n') + '\n',
      10,
      5,
      100,
    ],
    [
      '100-line no trailing',
      'hundred_no_trail.txt',
      Array.from({ length: 100 }, (_, i) => `Line ${i + 1}`).join('\n'),
      0,
      5,
      100,
    ],
  ];

  for (const [label, name, content, offset, length, expected] of cases) {
    const filePath = await createTestFile(name, content);
    const result = await handleReadFile({ path: filePath, offset, length });
    const total = extractTotalLines(result);

    try {
      assert.strictEqual(total, expected, `${label}: expected ${expected}, got ${total}`);
      console.log(`  ✅ PASS: ${label} → total: ${total}`);
      passed++;
    } catch (error) {
      console.log(`  ❌ FAIL: ${error.message}`);
      failed++;
    }
  }

  console.log(`\n${passed} passed, ${failed} failed out of ${passed + failed} tests`);
  return failed;
}

function restoreEnvironment() {
  if (originalHome === undefined) {
    delete process.env.HOME;
  } else {
    process.env.HOME = originalHome;
  }

  if (originalUserProfile === undefined) {
    delete process.env.USERPROFILE;
  } else {
    process.env.USERPROFILE = originalUserProfile;
  }
}

let exitCode = 0;
try {
  await configManager.getConfig();
  await configManager.setValue('allowedDirectories', [testDir]);
  exitCode = (await testLineCount()) > 0 ? 1 : 0;
} catch (error) {
  console.error('Test error:', error);
  exitCode = 1;
} finally {
  restoreEnvironment();
  await Promise.all([
    fs.rm(isolatedHome, { recursive: true, force: true }),
    fs.rm(testDir, { recursive: true, force: true }),
  ]);
}

process.exit(exitCode);
