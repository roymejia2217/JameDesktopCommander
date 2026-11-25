import { z } from 'zod';
import type { ServerResult } from '../types.js';

const MAX_TEXT_BYTES = 1024 * 1024;
const MAX_PATH_BYTES = 4096;
const requestSchema = z.object({
    path: z.string().min(1).refine(value =>
        Buffer.byteLength(value, 'utf8') <= MAX_PATH_BYTES && !/[\u0000-\u001f\u007f]/u.test(value)),
    offset: z.number().int().min(-MAX_TEXT_BYTES).max(MAX_TEXT_BYTES).default(0),
    length: z.number().int().min(1).max(MAX_TEXT_BYTES).default(1000),
    isUrl: z.literal(false).optional(),
    origin: z.literal('llm').optional(),
}).strict();

export type ManagedReadRequest = Readonly<{
    path: string;
    offset: number;
    length: number;
}>;

export type ManagedReadResult =
    | { status: 'read'; text: string }
    | { status: 'denied' | 'unavailable' | 'unsupported' | 'not-found' };

/**
 * Internal startup dependency, never an MCP argument or a policy decision.
 * The enrolled broker must authenticate both endpoints, authorize the object
 * and enforce pagination, cancellation and bounded I/O before returning text.
 * This interface alone does not establish a protected broker.
 */
export type ManagedReadOperation = (
    request: ManagedReadRequest, signal: AbortSignal,
) => Promise<ManagedReadResult>;

function reject(code: string): ServerResult {
    return { content: [{ type: 'text', text: code }], isError: true };
}

/** No ambient filesystem access, config-root fallback or editor metadata. */
export async function handleManagedRead(
    operation: ManagedReadOperation, args: unknown, signal?: AbortSignal,
): Promise<ServerResult> {
    const parsed = requestSchema.safeParse(args);
    if (!parsed.success) return reject('E_NATIVE_READ_UNSUPPORTED');
    const deadline = AbortSignal.timeout(30_000);
    const bounded = signal ? AbortSignal.any([signal, deadline]) : deadline;
    if (bounded.aborted) return reject('E_NATIVE_READ_CANCELLED');
    const { path, offset, length } = parsed.data;
    try {
        const reply = await operation(Object.freeze({ path, offset, length }), bounded);
        if (bounded.aborted) return reject('E_NATIVE_READ_CANCELLED');
        switch (reply.status) {
            case 'read':
                if (typeof reply.text !== 'string' ||
                    Buffer.byteLength(reply.text, 'utf8') > MAX_TEXT_BYTES) {
                    return reject('E_NATIVE_READ_UNSUPPORTED');
                }
                return { content: [{ type: 'text', text: reply.text }], isError: false };
            case 'denied': return reject('E_NATIVE_READ_DENIED');
            case 'unsupported': return reject('E_NATIVE_READ_UNSUPPORTED');
            case 'not-found': return reject('E_NATIVE_READ_NOT_FOUND');
            default: return reject('E_NATIVE_AUTHORITY_UNAVAILABLE');
        }
    } catch {
        return reject(bounded.aborted
            ? 'E_NATIVE_READ_CANCELLED' : 'E_NATIVE_AUTHORITY_UNAVAILABLE');
    }
}
