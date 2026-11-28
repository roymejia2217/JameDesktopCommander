import { addAbortListener } from 'node:events';
import { z } from 'zod';
import type { ServerResult } from '../types.js';

// Narrow nonrelease text namespace. Do not silently reinterpret document,
// spreadsheet, script, or arbitrary-root legacy operations as plain text.
const MAX_BYTES = 1024 * 1024;
const pathSchema = z.string().refine(value => {
    if (!value.startsWith('/managed/')) return false;
    const name = value.slice('/managed/'.length);
    return name.length <= 255 && name.endsWith('.txt') && /^[A-Za-z0-9][A-Za-z0-9._-]*\.txt$/u.test(name)
        && !/^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)/iu.test(name);
});
const writeSchema = z.object({
    path: pathSchema,
    content: z.string().refine(value =>
        Buffer.byteLength(value, 'utf8') <= MAX_BYTES &&
        Buffer.from(value, 'utf8').toString('utf8') === value),
    mode: z.enum(['rewrite', 'append']).default('rewrite'),
    origin: z.literal('llm').optional(),
}).strict();
const moveSchema = z.object({ source: pathSchema, destination: pathSchema }).strict();

export type ManagedMutationRequest =
    | Readonly<{ kind: 'write'; path: string; content: string; mode: 'rewrite' | 'append' }>
    | Readonly<{ kind: 'move'; source: string; destination: string }>;

export type ManagedMutationResult = Readonly<{
    status: 'committed' | 'denied' | 'collision' | 'unsupported' | 'recovery-required';
}>;

/** Startup-only dependency. The protected broker, not this dispatcher,
 * decides create-vs-rewrite, authorizes the native object and persists
 * intent/result. A rejection means a confirmed nonmutation; disconnect,
 * timeout and uncertainty must never be reported as a clean rejection.
 * No automatic retry after submission. This is not an authority grant.
 */
export type ManagedMutationOperation = (
    request: ManagedMutationRequest, signal: AbortSignal,
) => Promise<ManagedMutationResult>;

function rejected(code: string): ServerResult {
    return { isError: true, content: [{ type: 'text', text: code }] };
}

export async function handleManagedMutation(
    operation: ManagedMutationOperation, name: string, args: unknown, signal?: AbortSignal,
): Promise<ServerResult> {
    let request: ManagedMutationRequest;
    if (name === 'write_file') {
        const parsed = writeSchema.safeParse(args);
        if (!parsed.success) return rejected('E_NATIVE_MUTATION_UNSUPPORTED');
        const { path, content, mode } = parsed.data;
        request = Object.freeze({ kind: 'write', path, content, mode });
    } else if (name === 'move_file') {
        const parsed = moveSchema.safeParse(args);
        if (!parsed.success) return rejected('E_NATIVE_MUTATION_UNSUPPORTED');
        const { source, destination } = parsed.data;
        request = Object.freeze({ kind: 'move', source, destination });
    } else {
        return rejected('E_NATIVE_MUTATION_UNSUPPORTED');
    }
    const deadline = AbortSignal.timeout(30_000);
    const bounded = signal ? AbortSignal.any([signal, deadline]) : deadline;
    if (bounded.aborted) return rejected('E_NATIVE_MUTATION_CANCELLED');
    let submitted = false;
    let abortListener: ReturnType<typeof addAbortListener> | undefined;
    const cancelled = new Promise<never>((_resolve, rejectAbort) => {
        abortListener = addAbortListener(bounded, () => rejectAbort(new Error('E_NATIVE_MUTATION_CANCELLED')));
    });
    try {
        const pending = Promise.resolve().then(() => {
            bounded.throwIfAborted();
            submitted = true;
            return operation(request, bounded);
        });
        const reply = await Promise.race([pending, cancelled]);
        if (bounded.aborted) return rejected(submitted ? 'E_NATIVE_MUTATION_OUTCOME_UNKNOWN' : 'E_NATIVE_MUTATION_CANCELLED');
        switch (reply.status) {
            case 'committed': return { isError: false, content: [{ type: 'text', text: 'NATIVE_MUTATION_COMMITTED' }] };
            case 'denied': return rejected('E_NATIVE_MUTATION_DENIED');
            case 'collision': return rejected('E_NATIVE_MUTATION_COLLISION');
            case 'unsupported': return rejected('E_NATIVE_MUTATION_UNSUPPORTED');
            default: return rejected('E_NATIVE_MUTATION_OUTCOME_UNKNOWN');
        }
    } catch {
        return rejected(submitted ? 'E_NATIVE_MUTATION_OUTCOME_UNKNOWN' : 'E_NATIVE_MUTATION_CANCELLED');
    } finally {
        abortListener?.[Symbol.dispose]();
    }
}


/** One startup-owned mutation channel. Do not queue or replay requests
 * after a lost acknowledgment; durable reconciliation belongs to the broker.
 * This in-process latch is supplementary, not a persistent recovery store.
 */
export function createManagedMutationDispatcher(operation: ManagedMutationOperation) {
    let busy = false;
    let recoveryRequired = false;
    return async (name: string, args: unknown, signal?: AbortSignal): Promise<ServerResult> => {
        if (recoveryRequired) return rejected('E_NATIVE_MUTATION_OUTCOME_UNKNOWN');
        if (busy) return rejected('E_NATIVE_MUTATION_BUSY');
        busy = true;
        try {
            const result = await handleManagedMutation(operation, name, args, signal);
            if (result.isError && result.content[0]?.type === 'text' &&
                result.content[0].text === 'E_NATIVE_MUTATION_OUTCOME_UNKNOWN') {
                recoveryRequired = true;
            }
            return result;
        } catch {
            recoveryRequired = true;
            return rejected('E_NATIVE_MUTATION_OUTCOME_UNKNOWN');
        } finally {
            busy = false;
        }
    };
}
