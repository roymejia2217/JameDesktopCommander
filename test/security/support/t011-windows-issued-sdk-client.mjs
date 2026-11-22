// Disposable Windows managed-client proof; never a shipping MCP launcher.
// The Rust test controls the process at CreateProcessW time and attests the
// kernel pipe peer before releasing an already-opened file object's bytes.
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';

try {
  if (process.platform !== 'win32' || process.argv.length !== 4) {
    throw new Error(`E_T011_WINDOWS_SDK_FIXTURE_ONLY argc=${process.argv.length}`);
  }
  // Dynamic import keeps import errors visible to the test-only diagnostics.
  const { exerciseIssuedSdkRead } = await import('./t011-issued-sdk-native-read.mjs');
  // This CI-only host exercises a second real process before native reply.
  const bytes = await exerciseIssuedSdkRead(process.argv[2], 9000);
  assert.deepEqual(bytes, Buffer.from([0x00, 0xff, 0x81, 0x2a, 0x4a, 0x44, 0x43, 0x0a]),
    'Official MCP SDK must return every original native byte, including NUL');
  console.error('T011_WINDOWS_ISSUED_SDK_EXACT_NATIVE_BYTES_PASS_NONRELEASE');
} catch (error) {
  // Test-only failure diagnostics, never input to the OS-identity decision.
  const log = process.env.JDC_T011_SDK_DIAGNOSTIC || process.argv[3];
  if (log) writeFileSync(log, String(error?.stack ?? error));
  throw error;
}
