import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import lockfile from 'proper-lockfile';
import { replaceFileWin32 } from '../../utils/windows-atomic-replace.js';

/** Strict persisted data; neither an authorization token nor a service controller. */
export interface DurableTunnelState {
    schemaVersion: 1;
    revision: number;
    desired: 'running' | 'stopped';
    retryAttempts: number;
    lastAttemptMs: number | null;
}
export type DurableTunnelUpdate = Pick<
    DurableTunnelState, 'desired' | 'retryAttempts' | 'lastAttemptMs'
>;
export interface DesiredStateStoreDependencies {
    replace?: (target: string, replacement: string) => Promise<void>;
}
const FIELDS = [
    'schemaVersion', 'revision', 'desired', 'retryAttempts', 'lastAttemptMs',
] as const;

export function parseDurableTunnelState(raw: string): DurableTunnelState {
    let data: unknown;
    try {
        data = JSON.parse(raw);
    } catch {
        throw new Error('Tunnel state is corrupt or is not valid JSON.');
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
        throw new Error('Tunnel state must be an object.');
    }
    const value = data as Record<string, unknown>;
    const keys = Object.keys(value);
    if (keys.length !== FIELDS.length ||
        keys.some((key) => !(FIELDS as readonly string[]).includes(key))) {
        throw new Error('Tunnel state has missing or unexpected fields.');
    }
    if (value.schemaVersion !== 1) {
        throw new Error('Unsupported tunnel state schema.');
    }
    if (!Number.isSafeInteger(value.revision) ||
        (value.revision as number) < 1 ||
        (value.revision as number) >= Number.MAX_SAFE_INTEGER) {
        throw new Error('Tunnel state revision is invalid.');
    }
    if (value.desired !== 'running' && value.desired !== 'stopped') {
        throw new Error('Tunnel desired state is invalid.');
    }
    if (!Number.isSafeInteger(value.retryAttempts) ||
        (value.retryAttempts as number) < 0 ||
        (value.retryAttempts as number) > 32) {
        throw new Error('Tunnel retry count is invalid.');
    }
    if (value.lastAttemptMs !== null &&
        (!Number.isSafeInteger(value.lastAttemptMs) ||
         (value.lastAttemptMs as number) < 0)) {
        throw new Error('Tunnel last attempt timestamp is invalid.');
    }
    if (((value.retryAttempts as number) === 0) !==
        (value.lastAttemptMs === null)) {
        throw new Error('Tunnel retry history is internally inconsistent.');
    }
    return Object.freeze(value) as unknown as DurableTunnelState;
}

/** A missing, corrupt or untrusted file must NEVER become an implicit Running state. */
export class TunnelDesiredStateStore {
    constructor(
        readonly filePath: string,
        private readonly deps: DesiredStateStoreDependencies = {},
    ) {
        if (typeof filePath !== 'string' || !path.isAbsolute(filePath) ||
            path.basename(filePath) !== 'tunnel-desired-state.json') {
            throw new Error('Tunnel state requires an explicit absolute state-file path.');
        }
    }

    private async requireRegularFile(): Promise<void> {
        const stats = await fs.lstat(this.filePath);
        if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1) {
            throw new Error('Tunnel state must be a regular, non-linked file.');
        }
    }

    async read(): Promise<DurableTunnelState> {
        await this.requireRegularFile();
        return parseDurableTunnelState(await fs.readFile(this.filePath, 'utf8'));
    }

    /** Conditional update only. Provisioning and operator authorization are external. */
    async compareAndSet(
        expectedRevision: number,
        update: DurableTunnelUpdate,
    ): Promise<DurableTunnelState> {
        if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1) {
            throw new Error('Expected revision is invalid.');
        }
        if (!update || typeof update !== 'object' || Array.isArray(update)) {
            throw new Error('Tunnel update must be an object.');
        }
        const proposed = update as unknown as Record<string, unknown>;
        if (Object.keys(proposed).length !== 3 ||
            Object.keys(proposed).some((key) =>
                !['desired', 'retryAttempts', 'lastAttemptMs'].includes(key))) {
            throw new Error('Tunnel update has missing or unexpected fields.');
        }
        await this.requireRegularFile();
        const release = await lockfile.lock(this.filePath, {
            realpath: true,
            stale: 30_000,
            update: 10_000,
            retries: { retries: 5, factor: 1.2, minTimeout: 10, maxTimeout: 100 },
        });
        try {
            const previous = await this.read();
            if (previous.revision !== expectedRevision) {
                throw new Error('Tunnel state revision conflict.');
            }
            const next = parseDurableTunnelState(JSON.stringify({
                schemaVersion: 1,
                revision: previous.revision + 1,
                ...update,
            }));
            const temporary = `${this.filePath}.${randomUUID()}.tmp`;
            let handle: Awaited<ReturnType<typeof fs.open>> | undefined;
            try {
                handle = await fs.open(temporary, 'wx', 0o600);
                await handle.writeFile(JSON.stringify(next) + '\n', 'utf8');
                await handle.sync();
                await handle.close();
                handle = undefined;
                if (this.deps.replace) {
                    await this.deps.replace(this.filePath, temporary);
                } else if (process.platform === 'win32') {
                    await replaceFileWin32(this.filePath, temporary);
                } else {
                    await fs.rename(temporary, this.filePath);
                }
                return next;
            } finally {
                if (handle) await handle.close().catch(() => {});
                await fs.unlink(temporary).catch((error: NodeJS.ErrnoException) => {
                    if (error.code !== 'ENOENT') throw error;
                });
            }
        } finally {
            await release();
        }
    }
}
