import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { PDFDocument } from 'pdf-lib';

const { readFileFromUrl } = await import('../dist/tools/filesystem.js');
const MAX_BYTES = 10 * 1024 * 1024;

async function withServer(handle, run) {
  const server = createServer(handle);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    await run(`http://127.0.0.1:${port}`);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve()));
  }
}
test('URL reader denies oversized declared text before returning content', async () => {
  await withServer((_req, res) => {
    res.writeHead(200, {
      'content-type': 'text/plain',
      'content-length': String(MAX_BYTES + 1),
    });
    res.end(Buffer.alloc(MAX_BYTES + 1, 65));
  }, async (base) => {
    await assert.rejects(readFileFromUrl(base + '/large.txt'), /E_URL_SIZE_DENIED/);
  });
});

test('URL reader denies oversized chunked image without disclosing partial bytes', async () => {
  await withServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'image/png' });
    const chunk = Buffer.alloc(1024 * 1024, 66);
    for (let index = 0; index < 11; index++) res.write(chunk);
    res.end();
  }, async (base) => {
    await assert.rejects(readFileFromUrl(base + '/image'), /E_URL_SIZE_DENIED/);
  });
});
test('URL reader preserves bounded text and image content', async () => {
  await withServer((req, res) => {
    if (req.url === '/image') {
      res.writeHead(200, { 'content-type': 'image/png' });
      res.end(Buffer.from([137, 80, 78, 71]));
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('SAFE_URL_CONTENT');
  }, async (base) => {
    const text = await readFileFromUrl(base + '/text');
    assert.equal(text.content, 'SAFE_URL_CONTENT');
    const image = await readFileFromUrl(base + '/image');
    assert.equal(image.content, Buffer.from([137, 80, 78, 71]).toString('base64'));
    assert.equal(image.metadata.isImage, true);
  });
});

test('URL PDF is fetched only once and parsed from bounded bytes', async () => {
  const doc = await PDFDocument.create();
  doc.addPage([220, 300]);
  const pdf = Buffer.from(await doc.save());
  let fetches = 0;
  await withServer((_req, res) => {
    fetches++;
    res.writeHead(200, { 'content-type': 'application/pdf' });
    res.end(pdf);
  }, async (base) => {
    const result = await readFileFromUrl(base + '/sample.pdf');
    assert.equal(result.metadata.isPdf, true);
    assert.equal(result.metadata.totalPages, 1);
    assert.equal(fetches, 1);
  });
});

// node-fetch transparently decompresses gzip; the quota must apply to the
// decoded body, not to its much smaller Content-Length header.
test('URL reader rejects gzip-expanded text past its actual-byte budget', async () => {
  const { gzipSync } = await import('node:zlib');
  const encoded = gzipSync(Buffer.alloc(MAX_BYTES + 1, 65));
  assert.ok(encoded.byteLength < MAX_BYTES);
  await withServer((_req, res) => {
    res.writeHead(200, {
      'content-type': 'text/plain',
      'content-encoding': 'gzip',
      'content-length': String(encoded.byteLength),
    });
    res.end(encoded);
  }, async (base) => {
    await assert.rejects(readFileFromUrl(base + '/compressed'), /E_URL_SIZE_DENIED/);
  });
});

test('URL reader accepts a response at the exact byte budget', async () => {
  await withServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(Buffer.alloc(MAX_BYTES, 67));
  }, async (base) => {
    const result = await readFileFromUrl(base + '/exact');
    assert.equal(Buffer.byteLength(result.content), MAX_BYTES);
  });
});
