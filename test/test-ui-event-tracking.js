/**
 * Tests for UI event tracking plumbing between apps and host interfaces.
 * It verifies stable envelopes plus client-side batching/backpressure behavior.
 */
import assert from 'assert';

import { server } from '../dist/server.js';
import { buildTrackUiEventCapturePayload } from '../dist/handlers/history-handlers.js';
import { createUiEventTracker } from '../dist/ui/shared/ui-event-tracker.js';

function getRequestHandler(method) {
  const handlers = server._requestHandlers;
  assert.ok(handlers, 'Server request handlers should be initialized');
  const handler = handlers.get(method);
  assert.ok(handler, `Expected request handler for ${method}`);
  return handler;
}

async function testTrackUiEventCall() {
  console.log('\n--- Test: track_ui_event call ---');
  const callToolHandler = getRequestHandler('tools/call');
  const response = await callToolHandler({
    method: 'tools/call',
    params: {
      name: 'track_ui_event',
      arguments: {
        event: 'widget_expanded',
        component: 'file_preview',
        params: {
          file_type: 'markdown',
          line_count: 36,
          expanded: true
        }
      }
    }
  }, {});

  assert.ok(response, 'tools/call should return a response');
  assert.ok(Array.isArray(response.content), 'track_ui_event should return content array');
  assert.strictEqual(response.isError, undefined, 'track_ui_event should not return isError');
  assert.ok(response.content[0].text.includes('Tracked UI event'), 'track_ui_event should acknowledge event tracking');
  console.log('✓ track_ui_event call works');
}

async function testTrackUiEventBatchCall() {
  console.log('\n--- Test: track_ui_event batch call ---');
  const callToolHandler = getRequestHandler('tools/call');
  const response = await callToolHandler({
    method: 'tools/call',
    params: {
      name: 'track_ui_event',
      arguments: {
        events: [
          {
            event: 'expand',
            component: 'file_preview',
            params: { file_type: 'markdown' }
          },
          {
            event: 'scroll_after_expand',
            component: 'file_preview',
            params: { file_type: 'markdown' }
          }
        ]
      }
    }
  }, {});

  assert.ok(response, 'batch tools/call should return a response');
  assert.strictEqual(response.isError, undefined, 'batch track_ui_event should not return isError');
  assert.ok(response.content[0].text.includes('2'), 'batch acknowledgement should include the event count');
  console.log('✓ track_ui_event batch call works');
}

async function testClientBatchingAndCoalescing() {
  console.log('\n--- Test: UI event tracker batches one frame ---');
  const calls = [];
  let scheduled;

  const tracker = createUiEventTracker(
    async (name, args) => {
      calls.push({ name, args });
      return {};
    },
    {
      component: 'file_preview',
      scheduleFlush: (callback) => {
        scheduled = callback;
      },
    }
  );

  tracker('scroll_after_expand', { file_type: 'markdown' });
  tracker('scroll_after_expand', { file_type: 'markdown' });
  tracker('expand', { file_type: 'markdown' });

  assert.strictEqual(calls.length, 0, 'events should not cross MCP before the scheduled flush');
  assert.ok(scheduled, 'one flush should be scheduled');

  await tracker.flush();

  assert.strictEqual(calls.length, 1, 'one frame should produce one MCP call');
  assert.strictEqual(calls[0].name, 'track_ui_event');
  assert.strictEqual(calls[0].args.events.length, 2, 'duplicate events should coalesce within the frame');

  const metrics = tracker.getMetrics();
  assert.deepStrictEqual(metrics, {
    queued: 3,
    coalesced: 1,
    dropped: 0,
    batchesSent: 1,
    eventsSent: 2,
  });

  console.log('✓ UI event tracker batches and coalesces');
}

async function testClientBackpressureDropsOldest() {
  console.log('\n--- Test: UI event tracker bounds pending events ---');
  const calls = [];
  let scheduled;
  const tracker = createUiEventTracker(
    async (name, args) => {
      calls.push({ name, args });
      return {};
    },
    {
      component: 'file_preview',
      maxPendingEvents: 2,
      scheduleFlush: (callback) => {
        scheduled = callback;
      },
    }
  );

  tracker('first', { value: 1 });
  tracker('second', { value: 2 });
  tracker('third', { value: 3 });

  assert.ok(scheduled, 'one flush should remain scheduled');
  await tracker.flush();

  assert.strictEqual(calls.length, 1, 'bounded pressure should still produce one MCP call');
  assert.deepStrictEqual(
    calls[0].args.events.map((event) => event.event),
    ['second', 'third'],
    'oldest pending event should be dropped under pressure'
  );
  assert.deepStrictEqual(tracker.getMetrics(), {
    queued: 3,
    coalesced: 0,
    dropped: 1,
    batchesSent: 1,
    eventsSent: 2,
  });

  console.log('✓ UI event tracker bounds pending events');
}

async function testTrackUiEventPayloadCollisionProtection() {
  console.log('\n--- Test: track_ui_event payload collision protection ---');
  const payload = buildTrackUiEventCapturePayload('widget_expanded', 'file_preview', {
    event: 'spoofed',
    component: 'spoofed_component',
    line_count: 12
  });

  assert.strictEqual(payload.event, 'widget_expanded', 'Canonical event should override params.event');
  assert.strictEqual(payload.component, 'file_preview', 'Canonical component should override params.component');
  assert.strictEqual(payload.line_count, 12, 'Custom params should be preserved');
  console.log('✓ track_ui_event payload collision protection works');
}

export default async function runTests() {
  try {
    await testTrackUiEventCall();
    await testTrackUiEventBatchCall();
    await testClientBatchingAndCoalescing();
    await testClientBackpressureDropsOldest();
    await testTrackUiEventPayloadCollisionProtection();
    console.log('\n✅ UI event tracking tests passed!');
    return true;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('❌ Test failed:', message);
    if (error instanceof Error && error.stack) {
      console.error(error.stack);
    }
    return false;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runTests().then((success) => {
    process.exit(success ? 0 : 1);
  }).catch((error) => {
    console.error('❌ Unhandled error:', error);
    process.exit(1);
  });
}
