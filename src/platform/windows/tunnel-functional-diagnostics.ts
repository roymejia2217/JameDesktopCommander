/**
 * Observational diagnostics from tunnel-client's local admin API.
 * This is not a fresh MCP tools/list or tools/call probe and cannot authorize restart.
 */
export interface TunnelFunctionalDiagnostics {
    kind: 'observational_only';
    localHealth: 'ready' | 'not_ready';
    mcpInitializeObserved: boolean | null;
    toolDiscovery: 'observed_complete' | 'observed_incomplete' | 'unverified';
    dispatcher: {
        active: number | null;
        failuresCumulative: number | null;
        timeoutsCumulative: number | null;
    };
    queueDepth: number | null;
    controlPlaneFailuresConsecutive: number | null;
}

const MAX_BYTES = 256 * 1024;
const TIMEOUT_MS = 5000;

function object(value: unknown): Record<string, unknown> | null {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? value as Record<string, unknown> : null;
}
function child(root: unknown, key: string): Record<string, unknown> | null {
    return object(object(root)?.[key]);
}
function count(root: unknown, key: string): number | null {
    const value = object(root)?.[key];
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
        ? value : null;
}
function boolean(root: unknown, key: string): boolean | null {
    const value = object(root)?.[key];
    return typeof value === 'boolean' ? value : null;
}

export function parseTunnelFunctionalHealth(raw: unknown): TunnelFunctionalDiagnostics {
    const root = object(raw);
    const components = child(root, 'components');
    if (!root || !components) {
        throw new Error('Tunnel health has no supported components object.');
    }
    const mcp = child(components, 'mcp');
    const dispatcher = child(components, 'dispatcher');
    const queue = child(components, 'queue');
    const controlPlane = child(components, 'control-plane');
    if (!mcp || !dispatcher || !queue || !controlPlane) {
        throw new Error('Tunnel health is missing required diagnostic components.');
    }
    const mcpDetails = child(mcp, 'details');
    const init = child(mcpDetails, 'initialize');
    const toolsList = child(mcpDetails, 'tools_list');
    const ok = boolean(toolsList, 'ok');
    const complete = boolean(toolsList, 'complete');
    const discovery = ok === true && complete === true
        ? 'observed_complete'
        : ok === false || complete === false
            ? 'observed_incomplete' : 'unverified';
    const ready = boolean(root, 'ready') === true && boolean(root, 'live') === true;
    return {
        kind: 'observational_only',
        localHealth: ready ? 'ready' : 'not_ready',
        mcpInitializeObserved: boolean(init, 'ok'),
        toolDiscovery: discovery,
        dispatcher: {
            active: count(child(dispatcher, 'details'), 'active'),
            failuresCumulative: count(child(dispatcher, 'details'), 'failures'),
            timeoutsCumulative: count(child(dispatcher, 'details'), 'timeouts'),
        },
        queueDepth: count(child(queue, 'details'), 'depth'),
        controlPlaneFailuresConsecutive:
            count(child(controlPlane, 'details'), 'consecutive_failures'),
    };
}

function verifiedLoopbackBaseUrl(baseUrl: string): URL {
    const url = new URL(baseUrl);
    if (url.protocol !== 'http:' ||
        (url.hostname !== '127.0.0.1' && url.hostname !== '[::1]') ||
        url.username || url.password || url.search || url.hash ||
        url.pathname !== '/' || !url.port) {
        throw new Error('Tunnel diagnostic URL must be an exact local HTTP endpoint.');
    }
    return url;
}

/**
 * Read-only bounded lookup; rejects redirects and does not print URLs,
 * credentials, tool names, command lines or untrusted diagnostic strings.
 */
export async function readTunnelFunctionalDiagnostics(
    baseUrl: string,
    fetchFn: typeof fetch = fetch,
): Promise<TunnelFunctionalDiagnostics> {
    const url = verifiedLoopbackBaseUrl(baseUrl);
    url.pathname = '/health';
    url.searchParams.set('details', 'true');
    const response = await fetchFn(url, {
        method: 'GET',
        redirect: 'error',
        cache: 'no-store',
        signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok || response.status !== 200 || !response.body) {
        throw new Error('Tunnel diagnostic endpoint did not return a valid response.');
    }
    const length = response.headers.get('content-length');
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BYTES)) {
        throw new Error('Tunnel diagnostic response exceeds allowed size.');
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    const reader = response.body.getReader();
    try {
        while (true) {
            const result = await reader.read();
            if (result.done) break;
            total += result.value.byteLength;
            if (total > MAX_BYTES) throw new Error('Tunnel diagnostic response exceeds allowed size.');
            chunks.push(result.value);
        }
    } finally {
        reader.releaseLock();
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    let parsed: unknown;
    try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    catch { throw new Error('Tunnel diagnostic response contains invalid JSON.'); }
    return parseTunnelFunctionalHealth(parsed);
}
