import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { DocxFileHandler, readDocxBytes } from '../dist/utils/files/docx.js';

const require = createRequire(import.meta.url);
const PizZip = require('pizzip');

function docxFixture() {
    const zip = new PizZip();
    zip.file('word/document.xml', [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">',
        '<w:body><w:p><w:r><w:t>Hello T011 DOCX</w:t></w:r></w:p>',
        '<w:p><w:r><w:t>Second paragraph</w:t></w:r></w:p></w:body></w:document>',
    ].join(''));
    return zip.generate({ type: 'nodebuffer', compression: 'DEFLATE' });
}

test('T011-C DOCX bytes: default outline from an in-memory Buffer', () => {
    const bytes = docxFixture();
    const original = Buffer.from(bytes);
    const result = readDocxBytes(bytes);
    assert.equal(result.mimeType, 'text/plain');
    assert.equal(result.metadata.isDocx, true);
    assert.match(result.content, /Hello T011 DOCX/);
    assert.match(result.content, /Second paragraph/);
    assert.deepEqual(bytes, original);
});

test('T011-C DOCX bytes: only the selected subarray is parsed', () => {
    const content = docxFixture();
    const backing = Buffer.concat([Buffer.from([0xff, 0x02]), content, Buffer.from([0xaa, 0xee])]);
    const bytes = Uint8Array.from(backing.subarray(2, content.length + 2));
    const result = readDocxBytes(bytes);
    assert.match(result.content, /Hello T011 DOCX/);
    assert.deepEqual(backing.subarray(0, 2), Buffer.from([0xff, 0x02]));
    assert.deepEqual(backing.subarray(content.length + 2), Buffer.from([0xaa, 0xee]));
});

test('T011-C DOCX bytes: XML pagination retains the existing contract', () => {
    const bytes = docxFixture();
    const result = readDocxBytes(bytes, { offset: 1, length: 100 });
    assert.equal(result.mimeType, 'application/xml');
    assert.equal(result.metadata.isDocx, true);
    assert.match(result.content, /^\[DOCX XML: lines 1-/);
    assert.match(result.content, /Hello T011 DOCX/);
});

test('T011-C DOCX bytes: source API denies filenames and invalid ZIPs', () => {
    assert.throws(() => readDocxBytes('private.docx'), TypeError);
    assert.throws(() => readDocxBytes(null), TypeError);
    assert.throws(() => readDocxBytes(Buffer.from('not-a-docx')));
    assert.throws(() => readDocxBytes(new Uint8Array()));
});

test('T011-C DOCX bytes: original path handler remains behavior-equivalent', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-t011-docx-byte-'));
    const file = path.join(directory, 'fixture.docx');
    const bytes = docxFixture();
    try {
        await fs.writeFile(file, bytes);
        const handler = new DocxFileHandler();
        assert.deepEqual(await handler.read(file), readDocxBytes(bytes));
        assert.deepEqual(
            await handler.read(file, { offset: -3, length: 2 }),
            readDocxBytes(bytes, { offset: -3, length: 2 }),
        );
    } finally {
        await fs.rm(directory, { recursive: true, force: true });
    }
});
