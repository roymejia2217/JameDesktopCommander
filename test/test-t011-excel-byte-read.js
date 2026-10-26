import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { ExcelFileHandler } from '../dist/utils/files/excel.js';

const require = createRequire(import.meta.url);
const ExcelJS = require('exceljs');
const LIMIT = 10 * 1024 * 1024;

async function workbookFixture() {
    const workbook = new ExcelJS.Workbook();
    const main = workbook.addWorksheet('Data');
    main.addRow(['Product', 'Quantity']);
    main.addRow(['Widget', 3]);
    main.addRow(['Gadget', 5]);
    const secondary = workbook.addWorksheet('Named Sheet');
    secondary.addRow(['Field', 'Value']);
    secondary.addRow(['Active', true]);
    return Buffer.from(await workbook.xlsx.writeBuffer());
}

test('T011-C Excel byte reader: XLSX workbook and exact size metadata', async () => {
    const bytes = await workbookFixture();
    const snapshot = Buffer.from(bytes);
    const handler = new ExcelFileHandler();
    const result = await handler.readBytes(bytes);
    assert.equal(result.mimeType, 'application/json');
    assert.equal(result.metadata.isExcelFile, true);
    assert.equal(result.metadata.fileSize, bytes.byteLength);
    assert.equal(result.metadata.sheets.length, 2);
    assert.match(result.content, /Product/);
    assert.match(result.content, /Widget/);
    assert.deepEqual(bytes, snapshot, 'read must not mutate input bytes');
});

test('T011-C Excel byte reader: honors named-sheet range and row pagination', async () => {
    const handler = new ExcelFileHandler();
    const bytes = await workbookFixture();
    const result = await handler.readBytes(bytes, {
        range: "'Named Sheet'!A1:B2",
        offset: 1,
        length: 1,
    });
    assert.match(result.content, /Named Sheet/);
    assert.match(result.content, /Active/);
    assert.match(result.content, /true/);
    assert.doesNotMatch(result.content, /Widget/);
});

test('T011-C Excel byte reader: only the provided Buffer view is parsed', async () => {
    const bytes = await workbookFixture();
    const prefix = Buffer.from([0xaa, 0x00, 0xff]);
    const suffix = Buffer.from([0xdd, 0x11]);
    const backing = Buffer.concat([prefix, bytes, suffix]);
    const view = backing.subarray(prefix.length, prefix.length + bytes.length);
    const snapshot = Buffer.from(backing);
    assert.ok(view.byteOffset > 0);
    const result = await new ExcelFileHandler().readBytes(view);
    assert.equal(result.metadata.fileSize, bytes.byteLength);
    assert.match(result.content, /Gadget/);
    assert.deepEqual(backing, snapshot);
    const plain = await new ExcelFileHandler().readBytes(Uint8Array.from(view));
    assert.deepEqual(plain, result);
});

test('T011-C Excel byte reader: rejects pathname and oversize input before ZIP parsing', async () => {
    const handler = new ExcelFileHandler();
    await assert.rejects(handler.readBytes('C:/secrets.xlsx'), TypeError);
    await assert.rejects(handler.readBytes(null), TypeError);
    await assert.rejects(handler.readBytes(Buffer.alloc(LIMIT + 1)), /10MB/);
    await assert.rejects(handler.readBytes(Buffer.from('not an XLSX workbook')));
});

test('T011-C Excel byte reader: parity with the legacy pathname handler', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-t011-excel-'));
    const filename = path.join(directory, 'input.xlsx');
    try {
        const bytes = await workbookFixture();
        await fs.writeFile(filename, bytes);
        const handler = new ExcelFileHandler();
        assert.deepEqual(await handler.read(filename), await handler.readBytes(bytes, undefined, filename));
        const options = { sheet: 'Data', offset: 1, length: 1 };
        assert.deepEqual(await handler.read(filename, options), await handler.readBytes(bytes, options, filename));
    } finally {
        await fs.rm(directory, { recursive: true, force: true });
    }
});
