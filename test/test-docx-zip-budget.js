import assert from 'node:assert/strict';
import { test } from 'node:test';
import PizZip from 'pizzip';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readDocxBytes, DocxFileHandler } from '../dist/utils/files/docx.js';

function fixture(parts = {}) {
  const zip = new PizZip();
  zip.file('word/document.xml',
    '<w:document xmlns:w="urn:test"><w:body><w:p><w:r><w:t>Safe DOCX</w:t></w:r></w:p></w:body></w:document>');
  for (const [name, contents] of Object.entries(parts)) zip.file(name, contents);
  return zip.generate({ type: 'nodebuffer', compression: 'DEFLATE', compressionOptions: { level: 9 } });
}

test('DOCX budget: ordinary document with optional XML parts remains readable', async () => {
  const source = fixture({ 'word/header1.xml': '<w:hdr><w:t>Heading</w:t></w:hdr>' });
  const result = await readDocxBytes(source);
  assert.match(result.content, /Safe DOCX/);
  assert.match(result.content, /Heading/);
});

test('DOCX budget: rejects inflated XML exceeding the per-part limit', async () => {
  const source = fixture({ 'word/header1.xml': '<w:hdr>' + 'A'.repeat(9 * 1024 * 1024) + '</w:hdr>' });
  assert.ok(source.length < 1024 * 1024, 'fixture must really be highly compressed');
  await assert.rejects(async () => readDocxBytes(source), /DOCX.*(limit|budget)/i);
});

test('DOCX budget: rejects a ZIP archive with an excessive entry count', async () => {
  const zip = new PizZip();
  zip.file('word/document.xml', '<w:document><w:body/></w:document>');
  for (let i = 0; i < 1050; i++) zip.file('word/embeddings/obj' + i + '.xml', '<p/>');
  const source = zip.generate({ type: 'nodebuffer', compression: 'DEFLATE' });
  await assert.rejects(async () => readDocxBytes(source), /DOCX.*(limit|budget)/i);
});

test('DOCX budget: rejects oversized compressed input before opening archive', async () => {
  const payload = Buffer.alloc(10 * 1024 * 1024 + 1, 0);
  await assert.rejects(async () => readDocxBytes(payload), /DOCX.*(limit|budget)/i);
});

test('DOCX budget: aggregate inflation of distinct XML parts is bounded', async () => {
  const text = '<x>' + 'A'.repeat(6 * 1024 * 1024) + '</x>';
  const source = fixture(Object.fromEntries(
    Array.from({ length: 6 }, (_, i) => ['word/header' + (i + 1) + '.xml', text]),
  ));
  assert.ok(source.length < 1024 * 1024);
  await assert.rejects(() => readDocxBytes(source), /DOCX.*(limit|budget)/i);
});

test('DOCX budget: rejected edit preserves the existing ZIP bytes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'jdc-docx-budget-test-'));
  const path = join(root, 'source.docx');
  const source = fixture({ 'word/header1.xml': 'A'.repeat(9 * 1024 * 1024) });
  try {
    await writeFile(path, source);
    const result = await new DocxFileHandler().editRange(path, '', {
      old_string: 'Safe DOCX', new_string: 'Updated DOCX',
    });
    assert.equal(result.success, false);
    assert.deepEqual(await readFile(path), source, 'denied edit must not mutate the document');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('DOCX budget: accepted edit preserves ordinary DOCX functionality', async () => {
  const root = await mkdtemp(join(tmpdir(), 'jdc-docx-budget-test-'));
  const path = join(root, 'source.docx');
  try {
    await writeFile(path, fixture());
    const result = await new DocxFileHandler().editRange(path, '', {
      old_string: 'Safe DOCX', new_string: 'Edited DOCX',
    });
    assert.equal(result.success, true);
    const output = await readDocxBytes(await readFile(path));
    assert.match(output.content, /Edited DOCX/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('DOCX budget: pathname reader refuses oversized source and closes its handle', async () => {
  const root = await mkdtemp(join(tmpdir(), 'jdc-docx-budget-test-'));
  const path = join(root, 'oversize.docx');
  const source = Buffer.alloc(10 * 1024 * 1024 + 1, 0x61);
  try {
    await writeFile(path, source);
    await assert.rejects(() => new DocxFileHandler().read(path), /DOCX.*(limit|budget)/i);
    const edit = await new DocxFileHandler().editRange(path, '', {
      old_string: 'content', new_string: 'other',
    });
    assert.equal(edit.success, false);
    assert.deepEqual(await readFile(path), source, 'rejected operations must not change bytes');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
