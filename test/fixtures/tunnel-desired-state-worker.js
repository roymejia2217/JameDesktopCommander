import { TunnelDesiredStateStore } from '../../dist/platform/windows/tunnel-desired-state-store.js';

const [file, desired] = process.argv.slice(2);
const store = new TunnelDesiredStateStore(file);
try {
  const result = await store.compareAndSet(1, {
    desired, retryAttempts: 1, lastAttemptMs: 100,
  });
  process.send?.({ kind: 'completed', ok: true, revision: result.revision });
} catch (error) {
  process.send?.({
    kind: 'completed', ok: false,
    error: error instanceof Error ? error.message : 'unknown error',
    errorCode: error instanceof Error && typeof error.code === 'string'
      ? error.code : null,
  });
} finally {
  process.disconnect?.();
}
