import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { editPdfBytes, parsePdfBytesToMarkdown } from '../dist/tools/pdf/index.js';

const require = createRequire(import.meta.url);
const { PDFDocument } = require('pdf-lib');

// All fixtures are built in memory: no test source, output or sentinel path.
async function pdfWithPages(count) {
    const document = await PDFDocument.create();
    for (let i = 0; i < count; i++) {
        const page = document.addPage([300, 400]);
        page.drawText('T011 page ' + (i + 1), { x: 32, y: 300 });
    }
    return await document.save();
}

test('T011-C: PDF byte parser accepts Buffer and retains source bytes', async () => {
    const source = Buffer.from(await pdfWithPages(1));
    const snapshot = Buffer.from(source);
    const result = await parsePdfBytesToMarkdown(source);
    assert.equal(result.metadata.totalPages, 1);
    assert.deepEqual(result.pages.map(page => page.pageNumber), [1]);
    assert.deepEqual(source, snapshot);
});

test('T011-C: PDF parser handles a sliced Buffer without reading adjacent bytes', async () => {
    const sourcePdf = Buffer.from(await pdfWithPages(1));
    const backing = Buffer.concat([
        Buffer.from([0xff, 0x00, 0xaa]),
        sourcePdf,
        Buffer.from([0xee, 0x11]),
    ]);
    const source = backing.subarray(3, 3 + sourcePdf.length);
    const original = Buffer.from(backing);
    assert.ok(source.byteOffset > 0);
    const result = await parsePdfBytesToMarkdown(source);
    assert.equal(result.metadata.totalPages, 1);
    assert.deepEqual(backing, original);
});

test('T011-C: PDF byte editor removes pages without mutating input', async () => {
    const source = await pdfWithPages(2);
    const original = Uint8Array.from(source);
    const edited = await editPdfBytes(source, [{ type: 'delete', pageIndexes: [0] }]);
    const document = await PDFDocument.load(edited);
    assert.equal(document.getPageCount(), 1);
    assert.deepEqual(source, original);
});

test('T011-C: PDF byte editor inserts a separately supplied byte source', async () => {
    const target = await pdfWithPages(1);
    const insert = await pdfWithPages(2);
    const output = await editPdfBytes(target, [
        { type: 'insert', pageIndex: 1, sourcePdfBytes: insert },
    ]);
    assert.equal((await PDFDocument.load(output)).getPageCount(), 3);
});

test('T011-C: byte entry points reject pathname substitutes', async () => {
    const original = await pdfWithPages(1);
    await assert.rejects(parsePdfBytesToMarkdown('some/file.pdf'), TypeError);
    await assert.rejects(editPdfBytes('some/file.pdf', []), TypeError);
    await assert.rejects(editPdfBytes(original, [
        { type: 'insert', pageIndex: 0, sourcePdfPath: 'some/file.pdf' },
    ]), TypeError);
    await assert.rejects(editPdfBytes(original, [
        { type: 'insert', pageIndex: 0, sourcePdfBytes: await pdfWithPages(1), sourcePdfPath: 'some/file.pdf' },
    ]), TypeError);
    await assert.rejects(editPdfBytes(original, [
        { type: 'insert', pageIndex: 0, markdown: '# no URL or browser source' },
    ]), TypeError);
});

test('T011-C: byte editor rejects malformed operations before returning an output', async () => {
    const original = await pdfWithPages(1);
    await assert.rejects(editPdfBytes(original, null), TypeError);
    await assert.rejects(editPdfBytes(original, [
        { type: 'delete', pageIndexes: [0.5] },
    ]), TypeError);
    await assert.rejects(editPdfBytes(original, [
        { type: 'insert', pageIndex: Number.NaN, sourcePdfBytes: await pdfWithPages(1) },
    ]), TypeError);
    await assert.rejects(editPdfBytes(original, [{ type: 'rename', to: 'file.pdf' }]), TypeError);
});
