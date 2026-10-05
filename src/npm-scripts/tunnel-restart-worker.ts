import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import { restartWindowsTunnel } from '../platform/windows/tunnel-restart.js';

function parseTaskName(args: readonly string[]): string {
    if (args.length !== 2 || args[0] !== '--task-name') {
        throw new Error(
            'Usage: tunnel-restart-worker --task-name <scheduled-task-name>',
        );
    }
    const taskName = args[1]?.trim();
    if (!taskName || /[\0\r\n]/.test(taskName)) {
        throw new Error('Tunnel task name is invalid.');
    }
    return taskName;
}

export async function runTunnelRestartWorker(
    args: readonly string[] = process.argv.slice(2),
): Promise<void> {
    if (process.platform !== 'win32') {
        throw new Error(
            'Tunnel restart worker is supported only on Windows.',
        );
    }

    const taskName = parseTaskName(args);
    const result = await restartWindowsTunnel(taskName);
    process.stdout.write(
        JSON.stringify(
            {
                taskName,
                ...result,
            },
            null,
            2,
        ) + '\n',
    );
}

function isDirectExecution(): boolean {
    const entry = process.argv[1];
    if (!entry) {
        return false;
    }
    return import.meta.url === pathToFileURL(path.resolve(entry)).href;
}

if (isDirectExecution()) {
    runTunnelRestartWorker().catch((error) => {
        const message =
            error instanceof Error ? error.message : String(error);
        process.stderr.write(
            `Tunnel restart worker failed: ${message}\n`,
        );
        process.exitCode = 1;
    });
}
