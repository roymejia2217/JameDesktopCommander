import assert from 'node:assert/strict';
import { test } from 'node:test';
import { handleGetMoreSearchResults } from '../dist/handlers/search-handlers.js';
import { searchManager } from '../dist/search-manager.js';

const MAX_RESPONSE_BYTES = 1024 * 1024;
function page(results, hasMoreResults = false) {
  return {
    results, returnedCount: results.length, totalResults: results.length,
    totalMatches: results.length, isComplete: true, isError: false,
    hasMoreResults, runtime: 100,
  };
}

test('excessive requested result page is rejected without transmitting it', async t => {
  const entries = Array.from({ length: 9000 }, (_, i) => ({
    type: 'content', file: 'synthetic/'.padEnd(120, 'p'),
    line: i + 1, match: 'x'.repeat(95),
  }));
  t.mock.method(searchManager, 'readSearchResults', (_session, offset, length) =>
    page(entries.slice(offset, offset + length), offset + length < entries.length));
  const response = await handleGetMoreSearchResults({
    sessionId: 'test-only', offset: 0, length: entries.length,
  });
  assert.equal(response.isError, true, 'oversized tool reply must fail closed');
  assert.ok(Buffer.byteLength(response.content[0].text, 'utf8') <= MAX_RESPONSE_BYTES);
  assert.match(response.content[0].text, /smaller length/i);
  assert.doesNotMatch(response.content[0].text, /x{95}/,
    'the failure must not leak the unbounded result body');

  const retried = await handleGetMoreSearchResults({
    sessionId: 'test-only', offset: 0, length: 2,
  });
  assert.notEqual(retried.isError, true);
  assert.match(retried.content[0].text, /Showing results 0-1/);
  assert.match(retried.content[0].text, /offset: 2/,
    'a rejected page must not advance the session offset');
});

test('UTF-8 bytes, not JavaScript character count, determine page rejection', async t => {
  t.mock.method(searchManager, 'readSearchResults', () => page([
    { type: 'file', file: 'é'.repeat(600_000) },
  ]));
  const response = await handleGetMoreSearchResults({
    sessionId: 'test-only', offset: 0, length: 1,
  });
  assert.equal(response.isError, true);
  assert.ok(Buffer.byteLength(response.content[0].text, 'utf8') <= MAX_RESPONSE_BYTES);
});

test('an oversized session header is denied even for an empty page', async t => {
  t.mock.method(searchManager, 'readSearchResults', () => page([]));
  const response = await handleGetMoreSearchResults({
    sessionId: 'x'.repeat(MAX_RESPONSE_BYTES + 1), offset: 0, length: 1,
  });
  assert.equal(response.isError, true);
  assert.ok(Buffer.byteLength(response.content[0].text, 'utf8') <= MAX_RESPONSE_BYTES);
});

test('a page just under the byte budget remains available', async t => {
  t.mock.method(searchManager, 'readSearchResults', () => page([
    { type: 'file', file: 'a'.repeat(MAX_RESPONSE_BYTES - 512) },
  ]));
  const response = await handleGetMoreSearchResults({
    sessionId: 'test-only', offset: 0, length: 1,
  });
  assert.notEqual(response.isError, true);
  assert.ok(Buffer.byteLength(response.content[0].text, 'utf8') <= MAX_RESPONSE_BYTES);
  assert.match(response.content[0].text, /Search completed/);
});

test('bounded normal result pages retain the next-offset contract', async t => {
  t.mock.method(searchManager, 'readSearchResults', () => page([
    { type: 'content', file: 'alpha.txt', line: 1, match: 'alpha' },
    { type: 'content', file: 'beta.txt', line: 2, match: 'beta' },
  ], true));
  const response = await handleGetMoreSearchResults({
    sessionId: 'test-only', offset: 0, length: 2,
  });
  assert.notEqual(response.isError, true);
  assert.match(response.content[0].text, /alpha.txt:1/);
  assert.match(response.content[0].text, /beta.txt:2/);
  assert.match(response.content[0].text, /offset: 2/);
  assert.ok(Buffer.byteLength(response.content[0].text, 'utf8') <= MAX_RESPONSE_BYTES);
});
