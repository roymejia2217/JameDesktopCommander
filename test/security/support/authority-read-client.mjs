/**
 * T011 non-release read transport. This fixture does not ship in dist.
 * Production contracts are injected by the test after being compiled.
 * The Linux broker alone authenticates the OS principal and selects roots.
 */
import net from 'node:net';

const ISSUER_SOCKET = '/run/jdc-authority-ipc/authority.sock';
const READ_REPLY_HEADER_BYTES = 6;
const MAX_DEADLINE_MS = 30_000;

export class AuthorityReadTransportError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
    this.name = 'AuthorityReadTransportError';
  }
}

/** Returns no permission: only an authenticated native broker can do I/O. */
export function createIssuerReadClient({
  parseReadFileRequest,
  parseListDirectoryRequest,
  encodeAuthorityRequestFrame,
  decodeAuthorityReadReplyFrame,
  MAX_AUTHORITY_READ_PAYLOAD_BYTES,
}) {
  async function exchangeAuthorityReadFrame(socket, request, deadlineMs, operation = 'read-file') {
    let frame;
    try {
      if (!Number.isSafeInteger(deadlineMs) ||
          deadlineMs < 1 || deadlineMs > MAX_DEADLINE_MS) throw Error('deadline');
      const validate = operation === 'read-file' ? parseReadFileRequest
        : operation === 'list-directory' ? parseListDirectoryRequest : null;
      if (typeof validate !== 'function') throw Error('unsupported operation');
      frame = encodeAuthorityRequestFrame(validate(request));
    } catch {
      socket.destroy();
      throw new AuthorityReadTransportError('E_AUTHORITY_REQUEST_INVALID');
    }
    return new Promise((resolve, reject) => {
      const chunks = [];
      let total = 0;
      let finished = false;
      let timer;
      const cleanup = () => {
        clearTimeout(timer);
        socket.removeListener('connect', onConnect);
        socket.removeListener('data', onData);
        socket.removeListener('end', onEnd);
        socket.removeListener('error', onError);
        socket.removeListener('close', onClose);
      };
      const fail = (code) => {
        if (finished) return;
        finished = true;
        cleanup();
        socket.destroy();
        reject(new AuthorityReadTransportError(code));
      };
      const onConnect = () => {
        try {
          // The Rust AF_UNIX reader requires EOF after the exact frame.
          // Windows named pipes cannot use end(frame) to half-close here.
          if (process.platform === 'linux') socket.end(frame);
          else socket.write(frame);
        } catch {
          fail('E_AUTHORITY_UNAVAILABLE');
        }
      };
      const onData = chunk => {
        if (finished) return;
        total += chunk.length;
        if (total > MAX_AUTHORITY_READ_PAYLOAD_BYTES + READ_REPLY_HEADER_BYTES) {
          fail('E_AUTHORITY_REPLY_INVALID');
          return;
        }
        chunks.push(Buffer.from(chunk));
      };
      const onEnd = () => {
        if (finished) return;
        let result;
        try {
          result = decodeAuthorityReadReplyFrame(Buffer.concat(chunks, total));
        } catch {
          fail('E_AUTHORITY_REPLY_INVALID');
          return;
        }
        finished = true;
        cleanup();
        socket.destroy();
        resolve(result);
      };
      const onError = () => fail('E_AUTHORITY_UNAVAILABLE');
      const onClose = () => fail('E_AUTHORITY_REPLY_INVALID');
      timer = setTimeout(() => fail('E_AUTHORITY_TIMEOUT'), deadlineMs);
      socket.once('connect', onConnect);
      socket.on('data', onData);
      socket.once('end', onEnd);
      socket.once('error', onError);
      socket.once('close', onClose);
    });
  }
  async function exchangeAuthorityListFrame(socket, request, deadlineMs) {
    const result = await exchangeAuthorityReadFrame(socket, request, deadlineMs, 'list-directory');
    if (result.status !== 'ok') return result;
    try {
      const entries = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.bytes));
      if (!Array.isArray(entries) || entries.length > 256 ||
          entries.some((name, i) => typeof name !== 'string' ||
            name.length === 0 ||
            (i > 0 && entries[i - 1] >= name))) {
        throw Error('invalid listing');
      }
      for (const name of entries) {
        parseListDirectoryRequest({ ...request, relativePath: name });
        if (name.includes('/')) throw Error('nested listing entry');
      }
      return Object.freeze({
        version: 1, status: 'ok', entries: Object.freeze(entries),
      });
    } catch {
      throw new AuthorityReadTransportError('E_AUTHORITY_REPLY_INVALID');
    }
  }

  /** Test-only fixed endpoint: no caller-provided listener pathname. */
  async function requestIssuerOwnedRead(request, deadlineMs = 5_000) {
    if (process.platform !== 'linux') {
      throw new AuthorityReadTransportError('E_AUTHORITY_UNAVAILABLE');
    }
    try {
      parseReadFileRequest(request);
    } catch {
      throw new AuthorityReadTransportError('E_AUTHORITY_REQUEST_INVALID');
    }
    return exchangeAuthorityReadFrame(
      net.createConnection({ path: ISSUER_SOCKET }), request, deadlineMs,
    );
  }
  /** Fixed endpoint, protocol-tested read-only list request, never a grant. */
  async function requestIssuerOwnedList(request, deadlineMs = 5_000) {
    if (process.platform !== 'linux') {
      throw new AuthorityReadTransportError('E_AUTHORITY_UNAVAILABLE');
    }
    try {
      parseListDirectoryRequest(request);
    } catch {
      throw new AuthorityReadTransportError('E_AUTHORITY_REQUEST_INVALID');
    }
    return exchangeAuthorityListFrame(
      net.createConnection({ path: ISSUER_SOCKET }), request, deadlineMs,
    );
  }
  return Object.freeze({
    exchangeAuthorityReadFrame, exchangeAuthorityListFrame,
    requestIssuerOwnedRead, requestIssuerOwnedList,
  });
}
