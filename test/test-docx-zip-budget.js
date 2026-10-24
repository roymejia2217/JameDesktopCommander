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

function corruptBinaryDeflateMember(source, memberName) {
  // ZIP local-file header, PK 03 04; compressed length at +18,
  // filename length at +26, extra length at +28, payload starts at +30.
  // Use an invalid DEFLATE block type (0b11) without changing ZIP metadata.
  const bytes = Buffer.from(source);
  const filename = Buffer.from(memberName, 'utf8');
  const nameAt = bytes.indexOf(filename);
  assert.ok(nameAt >= 30, 'fixture must contain target member name');
  const header = nameAt - 30;
  assert.equal(bytes.readUInt32LE(header), 0x04034b50, 'local ZIP header must be present');
  assert.equal(bytes.readUInt16LE(header + 8), 8, 'fixture must use ZIP DEFLATE');
  const compressedSize = bytes.readUInt32LE(header + 18);
  const dataAt = header + 30 + bytes.readUInt16LE(header + 26) +
    bytes.readUInt16LE(header + 28);
  assert.ok(compressedSize > 16, 'fixture must contain a deflate stream');
  bytes[dataAt] = 0x06; // DEFLATE BTYPE=3 (reserved/invalid).
  return bytes;
}

test('DOCX budget: malformed embedded binary is rejected before PizZip processing', async () => {
  const source = fixture({
    'word/media/image1.bin': Buffer.from('VALID-EMBEDDED-BINARY-'.repeat(5000)),
  });
  const altered = corruptBinaryDeflateMember(source, 'word/media/image1.bin');
  assert.notDeepEqual(altered, source);
  await assert.rejects(() => readDocxBytes(altered),
    /invalid|inflation|inflate|deflate|zip|data|error/i,
    'a malformed non-XML ZIP entry must not pass an XML-only preflight');
});

test('DOCX budget: getInfo never loads an oversized archive with unbounded readFile', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'jdc-docx-info-budget-'));
  const path = join(root, 'oversize.docx');
  const size = 10 * 1024 * 1024 + 1;
  const fsPromises = (await import('node:fs/promises')).default;
  const original = fsPromises.readFile;
  let unboundedReads = 0;
  try {
    await writeFile(path, Buffer.alloc(size, 0x61));
    t.mock.method(fsPromises, 'readFile', async (...args) => {
      unboundedReads++;
      return original(...args);
    });
    const info = await new DocxFileHandler().getInfo(path);
    assert.equal(info.size, size);
    assert.equal(info.fileType, 'docx');
    assert.deepEqual(info.metadata, { isDocx: true });
    assert.equal(unboundedReads, 0, 'metadata inspection must not read unbounded file bytes');
  } finally {
    t.mock.restoreAll();
    await rm(root, { recursive: true, force: true });
  }
});

test('DOCX budget: getInfo rejects an overinflated entry without exposing document metadata', async () => {
  const root = await mkdtemp(join(tmpdir(), 'jdc-docx-info-budget-'));
  const path = join(root, 'overinflated.docx');
  const source = fixture({ 'word/header1.xml': '<w:hdr>' + 'A'.repeat(9 * 1024 * 1024) + '</w:hdr>' });
  try {
    await writeFile(path, source);
    const info = await new DocxFileHandler().getInfo(path);
    assert.equal(info.size, source.length);
    assert.deepEqual(info.metadata, { isDocx: true },
      'invalid inflated DOCX must not be parsed for detailed metadata');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('DOCX budget: getInfo retains detailed metadata for an ordinary validated archive', async () => {
  const root = await mkdtemp(join(tmpdir(), 'jdc-docx-info-budget-'));
  const path = join(root, 'valid.docx');
  const source = fixture();
  try {
    await writeFile(path, source);
    const info = await new DocxFileHandler().getInfo(path);
    assert.equal(info.size, source.length);
    assert.deepEqual(info.metadata, {
      isDocx: true,
      paragraphCount: 1,
      tableCount: 0,
      imageCount: 0,
      wordCount: 2,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
