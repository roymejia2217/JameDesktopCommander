import assert from 'node:assert/strict';

import {
  getPresentationMetrics,
  recordPresentationRender,
  resetPresentationMetrics,
} from '../dist/ui/file-preview/src/presentation-metrics.js';
import { createLatestRenderScheduler } from '../dist/ui/file-preview/src/presentation-scheduler.js';
import {
  MARKDOWN_EDITOR_CACHE_LIMIT,
  setBoundedMapEntry,
} from '../dist/ui/file-preview/src/presentation-state.js';
import { createUiEventTracker } from '../dist/ui/shared/ui-event-tracker.js';

function flushOnlyFrame(frames) {
  assert.equal(frames.size, 1, 'at most one render frame may be pending');
  const [id, callback] = frames.entries().next().value;
  frames.delete(id);
  callback();
}

async function testPresentationBurstSoak() {
  resetPresentationMetrics();

  let current = { id: 'initial' };
  let nextFrameId = 1;
  const frames = new Map();
  const rendered = [];

  const scheduler = createLatestRenderScheduler({
    schedule: (callback) => {
      const id = nextFrameId++;
      frames.set(id, callback);
      return id;
    },
    cancel: (id) => {
      frames.delete(id);
    },
    getCurrent: () => current,
    equivalent: (left, right) => left?.id === right?.id,
    render: (value) => {
      current = value;
      rendered.push(value?.id);
      recordPresentationRender();
    },
  });

  for (let index = 0; index < 10_000; index += 1) {
    scheduler.enqueue({ id: `initial-burst-${index}` });
    assert.ok(frames.size <= 1, 'bursts must never schedule more than one frame');
  }

  assert.equal(frames.size, 1, 'the initial 10k burst should collapse to one frame');
  flushOnlyFrame(frames);
  assert.equal(rendered.at(-1), 'initial-burst-9999', 'latest state must win the initial burst');

  for (let burst = 0; burst < 100; burst += 1) {
    for (let item = 0; item < 100; item += 1) {
      scheduler.enqueue({ id: `burst-${burst}-item-${item}` });
      assert.ok(frames.size <= 1, 'every burst must keep a single pending frame');
    }
    flushOnlyFrame(frames);
    assert.equal(
      rendered.at(-1),
      `burst-${burst}-item-99`,
      'each frame must render only the latest state in its burst',
    );
  }

  const metrics = getPresentationMetrics();
  assert.equal(metrics.updatesReceived, 20_000, 'soak should exercise 20k host updates');
  assert.equal(metrics.framesScheduled, 101, '20k updates should schedule only 101 frames');
  assert.equal(metrics.renderCalls, 101, 'render calls should track flushed frames, not incoming updates');
  assert.ok(metrics.updatesCoalesced >= 19_899, 'the overwhelming majority of burst updates should coalesce');
  assert.ok(
    metrics.renderCalls / metrics.updatesReceived < 0.01,
    'render amplification must stay below 1% under deterministic bursts',
  );
  assert.equal(frames.size, 0, 'all flushed frames must be released');

  scheduler.enqueue({ id: 'cancelled-a' });
  scheduler.enqueue({ id: 'cancelled-b' });
  assert.equal(frames.size, 1, 'cancel test should have one pending frame');
  const rendersBeforeCancel = rendered.length;
  scheduler.cancel();
  assert.equal(frames.size, 0, 'teardown cancellation must remove the pending render frame');
  assert.equal(rendered.length, rendersBeforeCancel, 'cancelled state must never render');
}

function testMarkdownCacheSoak() {
  const cache = new Map();

  for (let index = 0; index < 5_000; index += 1) {
    setBoundedMapEntry(cache, `file-${index}`, { index });
    assert.ok(
      cache.size <= MARKDOWN_EDITOR_CACHE_LIMIT,
      'Markdown editor metadata cache must remain bounded throughout the soak',
    );
  }

  assert.equal(cache.size, MARKDOWN_EDITOR_CACHE_LIMIT);
  assert.equal(cache.has('file-0'), false, 'old cache entries must be evicted');
  assert.equal(cache.has('file-4999'), true, 'latest cache entry must be retained');

  const expectedFirstRetained = 5_000 - MARKDOWN_EDITOR_CACHE_LIMIT;
  assert.equal(
    cache.keys().next().value,
    `file-${expectedFirstRetained}`,
    'cache should retain only the most recent bounded window',
  );

  setBoundedMapEntry(cache, 'file-4990', { index: 4990, refreshed: true });
  setBoundedMapEntry(cache, 'file-5000', { index: 5000 });
  assert.equal(cache.size, MARKDOWN_EDITOR_CACHE_LIMIT);
  assert.equal(cache.has('file-4990'), true, 'refreshing an entry must preserve it through LRU eviction');
}

async function testUiEventBatchSoak() {
  const calls = [];
  let scheduleCount = 0;

  const tracker = createUiEventTracker(
    async (name, args) => {
      calls.push({ name, args });
      return {};
    },
    {
      component: 'file_preview',
      scheduleFlush: () => {
        scheduleCount += 1;
      },
    },
  );

  for (let burst = 0; burst < 100; burst += 1) {
    for (let item = 0; item < 100; item += 1) {
      tracker('soak_event', {
        signature: item % 16,
        burst,
      });
    }
    await tracker.flush();
  }

  const metrics = tracker.getMetrics();
  assert.equal(metrics.queued, 10_000, 'analytics soak should exercise 10k UI events');
  assert.equal(scheduleCount, 100, 'each 100-event burst should request only one flush');
  assert.equal(metrics.batchesSent, 100, 'one batch should cross MCP per burst');
  assert.equal(metrics.eventsSent, 1_600, '16 unique signatures per burst should cap transport volume');
  assert.equal(metrics.coalesced, 8_400, 'duplicate signatures should coalesce inside each burst');
  assert.equal(metrics.dropped, 0, 'duplicate-heavy soak should stay within the 32-event pending bound');
  assert.equal(calls.length, 100, 'transport call count must be 100x lower than queued event count');
  assert.ok(
    metrics.batchesSent / metrics.queued <= 0.01,
    'analytics batch amplification must remain at or below 1%',
  );

  for (const call of calls) {
    const events = call.args.events ?? [call.args];
    assert.ok(events.length <= 32, 'no UI analytics batch may exceed the bounded pending capacity');
  }
}

async function testUiEventPressureAndCancellation() {
  const pressureCalls = [];
  let pressureScheduled = 0;

  const pressureTracker = createUiEventTracker(
    async (name, args) => {
      pressureCalls.push({ name, args });
      return {};
    },
    {
      component: 'file_preview',
      scheduleFlush: () => {
        pressureScheduled += 1;
      },
    },
  );

  for (let index = 0; index < 1_000; index += 1) {
    pressureTracker(`unique-${index}`, { index });
  }

  assert.equal(pressureScheduled, 1, '1k unique events must still schedule a single flush');
  await pressureTracker.flush();

  const pressureMetrics = pressureTracker.getMetrics();
  assert.equal(pressureMetrics.queued, 1_000);
  assert.equal(pressureMetrics.eventsSent, 32, 'bounded pressure must send at most 32 retained events');
  assert.equal(pressureMetrics.dropped, 968, 'oldest unique events must be evicted above the 32-event cap');
  assert.equal(pressureMetrics.batchesSent, 1);
  assert.equal(pressureCalls.length, 1);
  assert.equal(pressureCalls[0].args.events.length, 32);

  const cancelledCalls = [];
  let cancelledCallback;
  const cancelledTracker = createUiEventTracker(
    async (name, args) => {
      cancelledCalls.push({ name, args });
      return {};
    },
    {
      component: 'file_preview',
      scheduleFlush: (callback) => {
        cancelledCallback = callback;
      },
    },
  );

  cancelledTracker('teardown-event', { value: 1 });
  assert.equal(typeof cancelledCallback, 'function', 'teardown test must capture the scheduled flush');
  cancelledTracker.cancel();
  cancelledCallback();
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(cancelledCalls.length, 0, 'teardown must prevent pending analytics from crossing MCP');
  assert.deepEqual(cancelledTracker.getMetrics(), {
    queued: 1,
    coalesced: 0,
    dropped: 0,
    batchesSent: 0,
    eventsSent: 0,
  });
}

await testPresentationBurstSoak();
testMarkdownCacheSoak();
await testUiEventBatchSoak();
await testUiEventPressureAndCancellation();

console.log('Presentation soak/load stability contract: PASS');
