import assert from 'node:assert/strict';
import {
  getPresentationMetrics,
  recordPresentationMount,
  recordPresentationRender,
  resetPresentationMetrics,
} from '../dist/ui/file-preview/src/presentation-metrics.js';
import { createLatestRenderScheduler } from '../dist/ui/file-preview/src/presentation-scheduler.js';

resetPresentationMetrics();
recordPresentationMount();

let current = { id: 'current' };
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

scheduler.enqueue({ id: 'current' });
assert.equal(frames.size, 0, 'equivalent current state must not schedule a frame');

scheduler.enqueue({ id: 'a' });
scheduler.enqueue({ id: 'b' });
scheduler.enqueue({ id: 'c' });
assert.equal(frames.size, 1, 'bursty updates must share one scheduled frame');

const firstFrame = [...frames.entries()][0];
frames.delete(firstFrame[0]);
firstFrame[1]();

assert.deepEqual(rendered, ['c'], 'latest state must win within a frame');
assert.deepEqual(getPresentationMetrics(), {
  mounts: 1,
  renderCalls: 1,
  updatesReceived: 4,
  updatesCoalesced: 3,
  framesScheduled: 1,
});

scheduler.enqueue({ id: 'd' });
assert.equal(frames.size, 1);
scheduler.cancel();
assert.equal(frames.size, 0, 'cancel must remove a pending frame');
assert.deepEqual(rendered, ['c'], 'cancelled state must not render');

console.log('Presentation backpressure contract: PASS');
