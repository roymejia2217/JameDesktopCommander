import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import PizZip from 'pizzip';
import fsPromises from 'node:fs/promises';
import { SearchManager } from '../dist/search-manager.js';

function docx(xml) {
  const zip = new PizZip();
  zip.file('word/document.xml',
    '<w:document><w:body><w:p><w:r><w:t>Ordinary document</w:t></w:r></w:p></w:body></w:document>');
  zip.file('word/header1.xml', xml);
  return zip.generate({ type: 'nodebuffer', compression: 'DEFLATE', compressionOptions: { level: 9 } });
}

test('DOCX search: rejects inflated XML before search without modifying archive bytes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'jdc-docx-search-budget-'));
  const target = join(root, 'large.docx');
  const contents = docx('<w:hdr><w:t>BUDGET_NEEDLE' + 'A'.repeat(9 * 1024 * 1024) + '</w:t></w:hdr>');
  assert.ok(contents.length < 1024 * 1024, 'actual compressed ZIP must be small');
  try {
    await writeFile(target, contents);
    const manager = new SearchManager();
    const results = await manager.searchDocxFiles(root, 'BUDGET_NEEDLE', true, 10, '*.docx');
    assert.deepEqual(results, [], 'inflated XML must never reach searchable PizZip content');
    assert.deepEqual(await readFile(target), contents, 'rejected search must not mutate user file');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('DOCX search: ordinary bounded ZIP still returns genuine header text matches', async () => {
  const root = await mkdtemp(join(tmpdir(), 'jdc-docx-search-budget-'));
  const target = join(root, 'normal.docx');
  try {
    await writeFile(target, docx('<w:hdr><w:t>SEARCH_NEEDLE</w:t></w:hdr>'));
    const results = await new SearchManager().searchDocxFiles(root, 'SEARCH_NEEDLE', true, 10, '*.docx');
    assert.equal(results.length, 1);
    assert.match(results[0].match, /SEARCH_NEEDLE/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('DOCX search: bounded open replaces unbounded fs.readFile path', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'jdc-docx-search-budget-'));
  const target = join(root, 'normal.docx');
  let unboundedReads = 0;
  const original = fsPromises.readFile;
  try {
    await writeFile(target, docx('<w:hdr><w:t>SEARCH_NEEDLE</w:t></w:hdr>'));
    t.mock.method(fsPromises, 'readFile', async (...args) => {
      unboundedReads++;
      return original(...args);
    });
    const results = await new SearchManager().searchDocxFiles(root, 'SEARCH_NEEDLE', true, 10, '*.docx');
    assert.equal(results.length, 1, 'real positive control');
    assert.equal(unboundedReads, 0, 'search must not reopen whole DOCX by filename');
  } finally {
    t.mock.restoreAll();
    await rm(root, { recursive: true, force: true });
  }
});
