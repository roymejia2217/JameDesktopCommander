import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PDFDocument } from 'pdf-lib';

const configRoot = resolve(
  process.env.DESKTOP_COMMANDER_TEST_CONFIG_ROOT || '.tmp/test-config',
  String(process.pid),
);
assert.equal(
  process.env.DESKTOP_COMMANDER_CONFIG_DIR && resolve(process.env.DESKTOP_COMMANDER_CONFIG_DIR),
  configRoot,
  'E_TEST_ISOLATION_REQUIRED: use test config preloader',
);

const { configManager } = await import('../dist/config-manager.js');
const { writePdf } = await import('../dist/tools/filesystem.js');
const { handleWritePdf } = await import('../dist/handlers/filesystem-handlers.js');
async function withPdf(mode, operation) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-t011-write-pdf-'));
  const allowed = join(root, 'allowed');
  const source = join(allowed, 'source.pdf');
  const output = join(allowed, 'output.pdf');
  const outside = join(root, 'sentinel.txt');
  await mkdir(allowed);
  const doc = await PDFDocument.create();
  doc.addPage([250, 300]);
  doc.addPage([250, 300]);
  const original = Buffer.from(await doc.save());
  await writeFile(source, original);
  await writeFile(outside, 'EXTERNAL_UNCHANGED');
  const previous = configManager.getAllowedDirectoriesForFilesystem;
  configManager.getAllowedDirectoriesForFilesystem = async () => {
    if (mode === 'unavailable') throw new Error('policy persistence unavailable');
    if (mode === 'unset') return undefined;
    return mode === 'restricted' ? [allowed] : [];
  };
  try {
    await operation({ source, output, original });
    assert.equal(await readFile(outside, 'utf8'), 'EXTERNAL_UNCHANGED');
  } finally {
    configManager.getAllowedDirectoriesForFilesystem = previous;
    await rm(root, { recursive: true, force: true });
  }
}
const deletion = [{ type: 'delete', pageIndexes: [1] }];

for (const mode of ['restricted', 'unavailable', 'unset']) {
  test(`T011 #139 ${mode} denies direct PDF rewrite and handler output before I/O`, async () => {
    await withPdf(mode, async ({ source, output, original }) => {
      await assert.rejects(writePdf(source, deletion, output), /E_POLICY_UNAVAILABLE/);
      const result = await handleWritePdf({ path: source, content: deletion, outputPath: output });
      assert.equal(result.isError, true, 'PDF tool must not announce a successful write');
      assert.match(result.content[0].text, /E_POLICY_UNAVAILABLE/);
      assert.deepEqual(await readFile(source), original, 'original PDF bytes must be unchanged');
      await assert.rejects(readFile(output), { code: 'ENOENT' });
    });
  });
}

test('T011 #139 restricted in-place PDF operation cannot change source bytes', async () => {
  await withPdf('restricted', async ({ source, original }) => {
    await assert.rejects(writePdf(source, deletion), /E_POLICY_UNAVAILABLE/);
    assert.deepEqual(await readFile(source), original);
  });
});
test('T011 #139 explicitly unrestricted PDF editing retains source and writes destination', async () => {
  await withPdf('unrestricted', async ({ source, output, original }) => {
    const result = await handleWritePdf({
      path: source, content: deletion, outputPath: output,
    });
    assert.notEqual(result.isError, true, result.content[0].text);
    const modified = await PDFDocument.load(await readFile(output));
    assert.equal(modified.getPageCount(), 1);
    assert.deepEqual(await readFile(source), original, 'source PDF must not be overwritten');
  });
});

// Markdown creation must be denied before invoking PDF rendering or writing a
// new output. This also keeps offline tests independent of Chrome downloads.
test('T011 #139 restricted PDF creation cannot write an output or invoke conversion', async () => {
  await withPdf('restricted', async ({ source, output, original }) => {
    await assert.rejects(writePdf(source, '# Denied', output), /E_POLICY_UNAVAILABLE/);
    const response = await handleWritePdf({
      path: source, content: '# Denied', outputPath: output,
    });
    assert.equal(response.isError, true);
    assert.match(response.content[0].text, /E_POLICY_UNAVAILABLE/);
    await assert.rejects(readFile(output), { code: 'ENOENT' });
    assert.deepEqual(await readFile(source), original);
  });
});
