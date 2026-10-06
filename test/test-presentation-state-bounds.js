import assert from 'node:assert/strict';
import {
  MARKDOWN_EDITOR_CACHE_LIMIT,
  areRenderPayloadsEquivalent,
  setBoundedMapEntry,
} from '../dist/ui/file-preview/src/presentation-state.js';

const base = {
  fileName: 'README.md',
  filePath: 'E:\\repo\\README.md',
  fileType: 'markdown',
  sourceTool: 'read_file',
  defaultEditorName: 'Code',
  defaultEditorPath: 'C:\\Code.exe',
  content: '# Hello',
  mimeType: 'text/markdown',
};

assert.equal(areRenderPayloadsEquivalent(base, { ...base }), true, 'identical payloads should coalesce');
for (const key of ['fileName', 'filePath', 'fileType', 'sourceTool', 'defaultEditorName', 'defaultEditorPath', 'content', 'mimeType']) {
  const changed = { ...base, [key]: String(base[key]) + '-changed' };
  assert.equal(areRenderPayloadsEquivalent(base, changed), false, key + ' changes must remain render-significant');
}
assert.equal(areRenderPayloadsEquivalent(undefined, undefined), true);
assert.equal(areRenderPayloadsEquivalent(base, undefined), false);

const cache = new Map();
setBoundedMapEntry(cache, 'a', 1, 3);
setBoundedMapEntry(cache, 'b', 2, 3);
setBoundedMapEntry(cache, 'c', 3, 3);
setBoundedMapEntry(cache, 'a', 10, 3);
setBoundedMapEntry(cache, 'd', 4, 3);

assert.equal(cache.size, 3, 'cache must remain bounded');
assert.equal(cache.has('b'), false, 'least-recently-used entry should be evicted');
assert.equal(cache.get('a'), 10, 'refreshing a key should update its value and recency');
assert.deepEqual([...cache.keys()], ['c', 'a', 'd']);
assert.ok(MARKDOWN_EDITOR_CACHE_LIMIT >= 8 && MARKDOWN_EDITOR_CACHE_LIMIT <= 128, 'production cache limit must be deliberately bounded');

console.log('Presentation state bounds contract: PASS');
