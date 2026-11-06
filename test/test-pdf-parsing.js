import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePdfToMarkdown } from '../dist/tools/pdf/index.js';

const samples = join(dirname(fileURLToPath(import.meta.url)), 'samples');
const simplePdf = join(samples, '01_sample_simple.pdf');
const complexPdf = join(samples, '03_sample_compex.pdf');

for (const [name, pages] of [
  ['01_sample_simple.pdf', 1],
  ['02_sample_invoice.pdf', 1],
  ['03_sample_compex.pdf', 22],
]) {
  test(`parses local PDF fixture ${name}`, async () => {
    const result = await parsePdfToMarkdown(join(samples, name));
    assert.equal(result.pages.length, pages);
    assert.ok(result.pages.some(page => page.text.trim().length > 0));
    if (name === '02_sample_invoice.pdf') {
      assert.ok(result.pages[0].images.length > 0, 'invoice images must be extracted');
    }
  });
}

test('PDF page selection returns the requested pages and bounded ranges', async () => {
  const selections = [
    [[1], [1]],
    [{ offset: 0, length: 1 }, [1]],
    [{ offset: -2, length: 2 }, [21, 22]],
    [{ offset: 0, length: 100 }, Array.from({ length: 22 }, (_, index) => index + 1)],
    [{ offset: -100, length: 100 }, Array.from({ length: 22 }, (_, index) => index + 1)],
    [[1, 5, 14], [1, 5, 14]],
  ];
  for (const [selection, expected] of selections) {
    const result = await parsePdfToMarkdown(complexPdf, selection);
    assert.deepEqual(result.pages.map(page => page.pageNumber), expected);
  }
});

test('parses a PDF fetched from a local HTTP server', async () => {
  const bytes = await readFile(simplePdf);
  let requests = 0;
  const server = createServer((_request, response) => {
    requests++;
    response.writeHead(200, { 'content-type': 'application/pdf' });
    response.end(bytes);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const result = await parsePdfToMarkdown(`http://127.0.0.1:${server.address().port}/sample.pdf`);
    assert.equal(requests, 1);
    assert.equal(result.pages.length, 1);
    assert.match(result.pages[0].text, /Hello World/);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
