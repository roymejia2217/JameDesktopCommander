import assert from 'node:assert/strict';
import { test } from 'node:test';
import { appendFile, mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import * as lifecycle from '../dist/platform/linux/tunnel-lifecycle.js';

const LIMIT = 1024 * 1024;
async function withProfile(data, check) {
  const dir = await mkdtemp(path.join(tmpdir(), 'jdc-linux-profile-bound-'));
  const name = path.join(dir, 'profile.yaml');
  try {
    await writeFile(name, data);
    const file = await open(name, 'r');
    try { await check(file, name); } finally { await file.close(); }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('registered status reader preserves exact bounded UTF-8 content and empty files', async () => {
  assert.equal(typeof lifecycle.readBoundedStatusProfileFile, 'function');
  for (const text of ['', 'health:\n  url_file: /tmp/óptimo\n']) {
    await withProfile(text, async (file) => {
      assert.equal(await lifecycle.readBoundedStatusProfileFile(file), text);
    });
  }
});

test('registered status reader accepts a file of exactly 1 MiB', async () => {
  await withProfile(Buffer.alloc(LIMIT, 0x61), async (file) => {
    const contents = await lifecycle.readBoundedStatusProfileFile(file);
    assert.equal(contents.length, LIMIT);
    assert.equal(contents[0], 'a');
    assert.equal(contents[contents.length - 1], 'a');
  });
});

test('registered status reader denies an oversized real file before parsing YAML', async () => {
  await withProfile(Buffer.alloc(LIMIT + 1, 0x61), async (file) => {
    await assert.rejects(lifecycle.readBoundedStatusProfileFile(file),
      /Linux tunnel status profile exceeds allowed size/);
    assert.equal((await file.stat()).size, LIMIT + 1,
      'rejection must not mutate the original profile file');
  });
});

test('registered status reader enforces its byte budget after a file grows', async () => {
  await withProfile('key: a\n', async (file, name) => {
    const changingFile = {
      stat: async () => {
        const previous = await file.stat();
        await appendFile(name, Buffer.alloc(LIMIT + 1, 0x61));
        return previous;
      },
      read: (...args) => file.read(...args),
      readFile: (...args) => file.readFile(...args),
    };
    await assert.rejects(lifecycle.readBoundedStatusProfileFile(changingFile),
      /Linux tunnel status profile exceeds allowed size/);
  });
});
