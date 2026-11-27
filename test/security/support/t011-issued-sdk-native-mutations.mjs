// Nonrelease vertical proof. Local Windows uses a guarded same-token child;
// hosted Linux uses the separately issued client and admitted mount.
import { connect, Socket } from 'node:net';
import { readSync, writeSync } from 'node:fs';
import { addAbortListener, once } from 'node:events';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const [socketPath, localHome, scenario, completionPath] = process.argv.slice(2);
const hostedCancellation = process.argv.length === 4 && localHome === '--hosted-cancel-before-commit';
const hosted = process.argv.length === 3 || hostedCancellation;
const inherited = socketPath === '--inherited-channel';
const windowsCancellation = process.platform === 'win32' && inherited && !hosted &&
  scenario === '--cancel-before-commit' && process.argv.length === 6 &&
  /^\\\\\.\\pipe\\JDC-T011-MUTATION-\d+-\d+-completion$/.test(completionPath ?? '');
const localCancellation = scenario === '--cancel-before-commit' && !hosted &&
  ((process.platform === 'linux' && !inherited) || windowsCancellation);
const cancelBeforeCommit = hostedCancellation || localCancellation;
if (scenario && !localCancellation) throw Error('E_MUTATION_FIXTURE_SCENARIO');
if (inherited && (process.platform !== 'win32' || hosted)) throw Error('E_INHERITED_FIXTURE_PLATFORM');
if (!['linux', 'win32'].includes(process.platform) || !socketPath ||
    (hosted ? (process.platform !== 'linux' || process.getuid?.() === 0 ||
        process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted')
      : (!localHome || process.argv.length !== (windowsCancellation ? 6 : localCancellation ? 5 : 4)))) {
  throw Error('E_MUTATION_FIXTURE_ARGS');
}
if (hosted) {
  // Private issuer readiness socket, separate from the mutation transport.
  const release = Buffer.alloc(1);
  if (writeSync(0, 'R') !== 1 || readSync(0, release, 0, 1, null) !== 1 || release[0] !== 0x41) {
    throw Error('E_T011_SDK_STARTUP_PROTOCOL');
  }
}
const home = hosted ? fileURLToPath(new URL('../../../client-state/', import.meta.url)) : localHome;
process.env.HOME = home;
process.env.DESKTOP_COMMANDER_CONFIG_DIR = home;
process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';
process.env.DC_FLAG_URL = 'http://127.0.0.1:9/';
const { createJdcServer } = await import('../../../dist/server.js');

function encode(request) {
  // Fixed proof protocol, not a general authority-frame version. Only
  // fields forwarded by the real managed dispatcher are serialized.
  const tag = request.kind === 'move' ? 3 : request.mode === 'append' ? 2 : 1;
  const fields = request.kind === 'move'
    ? [request.source, request.destination]
    : [request.path, request.content];
  const parts = [Buffer.from([tag])];
  for (const field of fields) {
    const bytes = Buffer.from(field, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    parts.push(length, bytes);
  }
  const payload = Buffer.concat(parts);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(payload.length);
  return Buffer.concat([length, payload]);
}
let submitted = 0;
let lostAckObserved = false;
let stagedCancellationObserved = false;
const cancellation = cancelBeforeCommit ? new AbortController() : undefined;
// The issuer supplies an already connected duplex endpoint as fd 0.
// No path open, and stdout/stderr remain separate diagnostic channels.
const issuedChannel = inherited ? new Socket({ fd: 0, readable: true, writable: true }) : undefined;
const issuedReader = issuedChannel?.[Symbol.asyncIterator]();
let issuedReady = false;
async function mutateInherited(request, signal) {
  const bounded = AbortSignal.any([signal, AbortSignal.timeout(25000)]);
  const cancel = addAbortListener(bounded, () => {
    // On Windows libuv retains the original standard descriptor. Send an
    // explicit cancellation only for the forwarded MCP abort, not a timeout.
    if (windowsCancellation && stagedCancellationObserved && signal.aborted) {
      issuedChannel.write('X', () => issuedChannel.destroy(new Error('E_CHANNEL_CANCELLED')));
    } else {
      issuedChannel.destroy(new Error('E_CHANNEL_CANCELLED'));
    }
  });
  try {
    bounded.throwIfAborted();
    // Signal readiness only when the real SDK dispatcher first reaches the
    // transport; startup time is not part of the per-frame service deadline.
    if (!issuedReady) {
      await new Promise((resolve, reject) => issuedChannel.write('R', error => error ? reject(error) : resolve()));
      issuedReady = true;
    }
    const challenge = await issuedReader.next();
    if (challenge.done || challenge.value.length !== 1 || challenge.value[0] !== 0x43)
      throw Error('E_CHALLENGE');
    await new Promise((resolve, reject) => issuedChannel.write(encode(request), error => error ? reject(error) : resolve()));
    const reply = await issuedReader.next();
    if (windowsCancellation && !reply.done && reply.value.length === 1 && reply.value[0] === 0x53) {
      if (stagedCancellationObserved) throw Error('E_DUPLICATE_STAGE');
      stagedCancellationObserved = true;
      // Cancel the actual MCP request. Its forwarded abort signal must
      // deliver the explicit cancellation frame before native disconnection.
      cancellation.abort(new Error('E_TEST_CANCEL_AT_STAGED_BOUNDARY'));
      await issuedReader.next();
      bounded.throwIfAborted();
      throw Error('E_CANCELLATION_NOT_PROPAGATED');
    }
    bounded.throwIfAborted();
    if (reply.done) {
      lostAckObserved = true;
      return { status: 'recovery-required' };
    }
    if (reply.value.length !== 1 || ![0x41, 0x44].includes(reply.value[0]))
      throw Error('E_RESULT');
    await new Promise((resolve, reject) => issuedChannel.write('K', error => error ? reject(error) : resolve()));
    return { status: reply.value[0] === 0x41 ? 'committed' : 'denied' };
  } catch {
    issuedChannel.destroy();
    return { status: 'recovery-required' };
  } finally {
    cancel[Symbol.dispose]();
  }
}
async function mutate(request, signal) {
  submitted++;
  if (inherited) return mutateInherited(request, signal);
  const bounded = AbortSignal.any([signal, AbortSignal.timeout(process.platform === 'win32' ? 25000 : hosted ? 12000 : 5000)]);
  const channel = connect({ path: socketPath, signal: bounded });
  let challenged = false;
  let result;
  try {
    for await (const chunk of channel) {
      for (const byte of chunk) {
        if (!challenged) {
          if (byte !== 0x43) throw Error('E_CHALLENGE');
          challenged = true;
          channel.write(encode(request));
        } else {
          if (cancelBeforeCommit && byte === 0x53 && result === undefined && !stagedCancellationObserved) {
            stagedCancellationObserved = true;
            // Use the real MCP SDK request's cancellation path, not a
            // fabricated native cancellation flag or a killed process.
            cancellation.abort(new Error('E_TEST_CANCEL_AT_STAGED_BOUNDARY'));
            continue;
          }
          if (result !== undefined) throw Error('E_DUPLICATE_RESULT');
          result = byte;
          // On Windows prove the response was consumed before the server
          // closes this instance. Linux keeps its existing wire protocol.
          if (process.platform === 'win32' && (byte === 0x41 || byte === 0x44)) channel.write('K');
        }
      }
    }
    if (challenged && result === undefined) lostAckObserved = true;
    if (result === 0x41) return { status: 'committed' };
    if (result === 0x44) return { status: 'denied' };
    return { status: 'recovery-required' };
  } catch {
    return { status: 'recovery-required' };
  } finally {
    channel.destroy();
  }
}
const server = createJdcServer({ managedMutation: mutate });
const sdk = new Client({ name: 'desktop-commander-app', version: '1.0.0' });
const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
const write = (path, content, mode = 'rewrite') =>
  sdk.callTool({ name: 'write_file', arguments: { path, content, mode } });
const text = result => result.content[0].text;
try {
  await server.connect(serverTransport);
  await sdk.connect(clientTransport);
  if (cancelBeforeCommit) {
    // Separate test-owned completion channel keeps the issuing process
    // alive until the journal verdict is observed. Not an authority grant.
    const completion = connect({
      path: windowsCancellation ? completionPath : socketPath + '.completion',
      signal: AbortSignal.timeout(15000)
    });
    try {
      if (windowsCancellation) {
        await once(completion, 'connect');
        await new Promise((resolve, reject) => completion.write('R', error => error ? reject(error) : resolve()));
      }
      await assert.rejects(sdk.callTool({ name: 'write_file', arguments: {
        path: '/managed/cancelled.txt', content: 'MUST-NOT-PUBLISH'
      } }, undefined, { signal: cancellation.signal }));
      assert.equal(stagedCancellationObserved, true, 'cancellation must follow the native staging event');
      let verdict = '';
      for await (const chunk of completion) {
        assert.equal(verdict.length + chunk.length, 1, 'one completion byte required');
        verdict += chunk.toString('ascii');
        if (windowsCancellation) {
          assert.equal(verdict, 'V');
          await new Promise((resolve, reject) => completion.write('K', error => error ? reject(error) : resolve()));
        }
      }
      assert.equal(verdict, 'V', 'native service must confirm terminal journal verdict');
      assert.equal(text(await write('/managed/cancelled.txt', 'RETRY')), 'E_NATIVE_MUTATION_OUTCOME_UNKNOWN');
      assert.equal(submitted, 1, 'cancelled submitted operation must not be retried');
      console.error(windowsCancellation
        ? 'T011_WINDOWS_REAL_SDK_CANCELLED_BEFORE_COMMIT_PASS_NONRELEASE'
        : hostedCancellation
          ? 'T011_LINUX_ROOT_ISSUED_SDK_CANCELLED_BEFORE_COMMIT_PASS_NONRELEASE'
          : 'T011_LINUX_REAL_SDK_CANCELLED_BEFORE_COMMIT_PASS_NONRELEASE');
    } finally {
      completion.destroy();
    }
  } else {
  assert.equal(text(await write('/outside.txt', 'never')), 'E_NATIVE_MUTATION_UNSUPPORTED');
  assert.equal(submitted, 0);
  assert.equal(text(await write('/managed/ungranted.txt', 'never')), 'E_NATIVE_MUTATION_DENIED');
  for (const reply of [
    await write('/managed/report.txt', 'BEGIN'),
    await write('/managed/report.txt', '-APPEND', 'append'),
    await write('/managed/report.txt', 'REWRITE'),
    await sdk.callTool({ name: 'move_file', arguments: { source: '/managed/report.txt', destination: '/managed/final.txt' } }),
  ]) {
    assert.equal(reply.isError, false);
    assert.equal(text(reply), 'NATIVE_MUTATION_COMMITTED');
  }
  assert.equal(text(await write('/managed/final.txt', '-LOST', 'append')), 'E_NATIVE_MUTATION_OUTCOME_UNKNOWN');
  assert.equal(lostAckObserved, true, 'must observe actual EOF without acknowledgment, not a timeout');
  assert.equal(text(await write('/managed/final.txt', '-RETRY', 'append')), 'E_NATIVE_MUTATION_OUTCOME_UNKNOWN');
  assert.equal(submitted, 6, 'must never submit after lost acknowledgment');
  console.error(inherited ? 'T011_WINDOWS_LOCAL_ISSUER_CONNECTED_SDK_MUTATION_CLIENT_PASS_NONRELEASE' : hosted ? 'T011_LINUX_ROOT_ISSUED_SDK_MUTATION_CLIENT_PASS_NONRELEASE' : `T011_${process.platform === 'win32' ? 'WINDOWS' : 'LINUX'}_LOCAL_REAL_JDC_JOURNALED_MUTATIONS_PASS_NONRELEASE`);
  }
} finally {
  issuedChannel?.destroy();
  await sdk.close();
  await server.close();
}
