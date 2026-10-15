import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';

/** Non-sensitive local correlation for a single Remote Device tool call. */
export type RemoteToolCallStage =
    | 'received'
    | 'duplicate_ignored'
    | 'claim_rejected'
    | 'claimed'
    | 'local_completed'
    | 'result_published'
    | 'execution_failed'
    | 'failure_published'
    | 'result_publish_failed';

const STAGES: readonly RemoteToolCallStage[] = [
    'received', 'duplicate_ignored', 'claim_rejected', 'claimed',
    'local_completed', 'result_published', 'execution_failed',
    'failure_published', 'result_publish_failed',
];

/** Logs only a local random receipt, fixed stage and monotonic elapsed time.
 * Never accepts or serializes call IDs, arguments, metadata, results or tokens.
 */
export function createRemoteCallReceipt(
    now: () => number = () => performance.now(),
    createId: () => string = randomUUID,
): (stage: RemoteToolCallStage) => string {
    const id = createId();
    const started = now();
    if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(id) ||
        !Number.isFinite(started)) {
        throw new Error('Invalid remote call receipt source.');
    }
    return (stage) => {
        if (!STAGES.includes(stage)) {
            throw new Error('Invalid remote call receipt stage.');
        }
        const elapsed = now() - started;
        if (!Number.isFinite(elapsed)) {
            throw new Error('Invalid remote call receipt clock.');
        }
        return `[JDC remote call] receipt=${id} stage=${stage} elapsed_ms=${Math.round(Math.max(0, elapsed))}`;
    };
}
