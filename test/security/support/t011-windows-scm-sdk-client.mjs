// Disposable fixed SCM SDK client; never packaged as a production entrypoint.
import assert from 'node:assert/strict';
import { exerciseIssuedJdcRead } from './t011-issued-sdk-native-read.mjs';

try {
  const pipe = process.argv[2];
  if (process.platform !== 'win32' || process.argv.length !== 3 ||
      typeof pipe !== 'string' || !/^\\\\\.\\pipe\\JDC-T011-SCM-SDK-[0-9a-f]{32}$/.test(pipe) ||
      !process.env.DESKTOP_COMMANDER_CONFIG_DIR) {
    throw Error('E_SCM_SDK_FIXED_CLIENT_REQUIRED');
  }
  const { createJdcServer } = await import('../../../dist/server.js');
  const bytes = await exerciseIssuedJdcRead(pipe, createJdcServer, 7000);
  assert.deepEqual(bytes, Buffer.from('SERVICE_DOMAIN_BYTES'));
  // Only the hosted controller may count this exit as evidence, after
  // authenticating the actual pinned process and native request.
  process.exit(19);
} catch {
  process.exit(1);
}
