import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import ExcelJS from 'exceljs';

const expectedConfig = resolve(
  process.env.DESKTOP_COMMANDER_TEST_CONFIG_ROOT || '.tmp/test-config',
  String(process.pid),
);
assert.equal(
  process.env.DESKTOP_COMMANDER_CONFIG_DIR && resolve(process.env.DESKTOP_COMMANDER_CONFIG_DIR),
  expectedConfig,
  'E_TEST_ISOLATION_REQUIRED: run with repository test preloader',
);

const { configManager } = await import('../dist/config-manager.js');
const { handleEditBlock, performSearchReplace } = await import('../dist/tools/edit.js');

async function withWorkbook(mode, operation) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-t011-edit-'));
  const allowed = join(root, 'allowed');
  const workbookPath = join(allowed, 'data.xlsx');
  const sentinel = join(root, 'outside.txt');
  await mkdir(allowed);
  const workbook = new ExcelJS.Workbook();
  workbook.addWorksheet('Sheet1').getCell('A1').value = 'ORIGINAL_VALUE';
  await workbook.xlsx.writeFile(workbookPath);
  await writeFile(sentinel, 'OUTSIDE_UNCHANGED');
  const before = await readFile(workbookPath);
  const prior = configManager.getAllowedDirectoriesForFilesystem;
  configManager.getAllowedDirectoriesForFilesystem = async () => {
    if (mode === 'unavailable') throw new Error('policy storage failed');
    if (mode === 'unset') return undefined;
    return mode === 'restricted' ? [allowed] : [];
  };
  try {
    await operation({ workbookPath, before });
    assert.equal(await readFile(sentinel, 'utf8'), 'OUTSIDE_UNCHANGED');
  } finally {
    configManager.getAllowedDirectoriesForFilesystem = prior;
    await rm(root, { recursive: true, force: true });
  }
}

for (const mode of ['restricted', 'unavailable', 'unset']) {
  test(`T011 #139 ${mode} denies specialized edit_block before modifying bytes`, async () => {
    await withWorkbook(mode, async ({ workbookPath, before }) => {
      const response = await handleEditBlock({
        file_path: workbookPath, range: 'Sheet1!A1:A1', content: [['CORRUPTED']],
      });
      assert.equal(response.isError, true, 'restricted specialized editor must not succeed');
      assert.match(response.content[0].text, /E_POLICY_UNAVAILABLE/);
      assert.deepEqual(await readFile(workbookPath), before, 'Excel original bytes must remain intact');
    });
  });
}

test('T011 #139 restricted standalone text editing denies before filesystem access', async () => {
  await withWorkbook('restricted', async ({ workbookPath, before }) => {
    await assert.rejects(
      performSearchReplace(workbookPath, { search: 'ORIGINAL', replace: 'CORRUPTED' }),
      /E_POLICY_UNAVAILABLE/,
    );
    assert.deepEqual(await readFile(workbookPath), before);
  });
});

test('T011 #139 explicit unrestricted mode preserves Excel range editing', async () => {
  await withWorkbook('unrestricted', async ({ workbookPath }) => {
    const response = await handleEditBlock({
      file_path: workbookPath, range: 'Sheet1!A1:A1', content: [['AUTHORIZED']],
    });
    assert.notEqual(response.isError, true, response.content[0].text);
    const updated = new ExcelJS.Workbook();
    await updated.xlsx.readFile(workbookPath);
    assert.equal(updated.getWorksheet('Sheet1').getCell('A1').value, 'AUTHORIZED');
  });
});
