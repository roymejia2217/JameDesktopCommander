import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
    buildSchtasksCreateArgs,
    buildWindowsTunnelTaskXml,
    encodeWindowsTaskXml,
    type WindowsTunnelTaskOptions,
} from './tunnel-task.js';

export type WindowsTunnelLifecycleAction = 'start' | 'stop' | 'uninstall';

export interface RunExecutableResult {
    stdout: string;
    stderr: string;
}

export type RunExecutable = (
    executable: string,
    args: readonly string[],
) => Promise<RunExecutableResult>;

export interface WindowsTunnelLifecycleDependencies {
    environment?: Record<string, string | undefined>;
    makeTempDirectory?: (prefix: string) => Promise<string>;
    writeFile?: (filePath: string, data: Buffer) => Promise<void>;
    removeDirectory?: (directory: string) => Promise<void>;
    runExecutable?: RunExecutable;
}

export interface InstallWindowsTunnelTaskOptions {
    taskName: string;
    task: WindowsTunnelTaskOptions;
}

function requireTaskName(taskName: string): string {
    const normalized = taskName.trim();
    if (!normalized) {
        throw new Error('Task name must not be empty.');
    }
    if (/[\0\r\n]/.test(normalized)) {
        throw new Error('Task name contains unsupported control characters.');
    }
    return normalized;
}

export function resolveSchtasksExecutable(
    environment: Record<string, string | undefined> = process.env,
): string {
    const systemRoot = environment.SystemRoot?.trim();
    if (!systemRoot || !path.win32.isAbsolute(systemRoot)) {
        throw new Error('SystemRoot must contain an absolute Windows path.');
    }
    return path.win32.join(systemRoot, 'System32', 'schtasks.exe');
}

export function buildSchtasksLifecycleArgs(
    action: WindowsTunnelLifecycleAction,
    taskName: string,
): string[] {
    const normalizedTaskName = requireTaskName(taskName);

    switch (action) {
        case 'start':
            return ['/Run', '/TN', normalizedTaskName];
        case 'stop':
            return ['/End', '/TN', normalizedTaskName];
        case 'uninstall':
            return ['/Delete', '/TN', normalizedTaskName, '/F'];
        default: {
            const exhaustiveCheck: never = action;
            throw new Error(`Unsupported lifecycle action: ${exhaustiveCheck}`);
        }
    }
}

const defaultRunExecutable: RunExecutable = async (executable, args) =>
    new Promise((resolve, reject) => {
        execFile(
            executable,
            [...args],
            {
                windowsHide: true,
                shell: false,
                encoding: 'utf8',
            },
            (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                    return;
                }
                resolve({ stdout, stderr });
            },
        );
    });

function resolveDependencies(
    dependencies: WindowsTunnelLifecycleDependencies,
): Required<WindowsTunnelLifecycleDependencies> {
    return {
        environment: dependencies.environment ?? process.env,
        makeTempDirectory:
            dependencies.makeTempDirectory ??
            ((prefix) => mkdtemp(prefix)),
        writeFile:
            dependencies.writeFile ??
            ((filePath, data) => writeFile(filePath, data)),
        removeDirectory:
            dependencies.removeDirectory ??
            ((directory) => rm(directory, { recursive: true, force: true })),
        runExecutable: dependencies.runExecutable ?? defaultRunExecutable,
    };
}

export async function installWindowsTunnelTask(
    options: InstallWindowsTunnelTaskOptions,
    dependencies: WindowsTunnelLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    const taskName = requireTaskName(options.taskName);
    const deps = resolveDependencies(dependencies);
    const schtasksExecutable = resolveSchtasksExecutable(deps.environment);
    const tempPrefix = path.join(os.tmpdir(), 'desktop-commander-tunnel-task-');
    const tempDirectory = await deps.makeTempDirectory(tempPrefix);
    const xmlPath = path.win32.join(tempDirectory, 'task.xml');

    try {
        const xml = buildWindowsTunnelTaskXml(options.task);
        await deps.writeFile(xmlPath, encodeWindowsTaskXml(xml));
        return await deps.runExecutable(
            schtasksExecutable,
            buildSchtasksCreateArgs(taskName, xmlPath),
        );
    } finally {
        await deps.removeDirectory(tempDirectory);
    }
}

async function runLifecycleAction(
    action: WindowsTunnelLifecycleAction,
    taskName: string,
    dependencies: WindowsTunnelLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    const deps = resolveDependencies(dependencies);
    return deps.runExecutable(
        resolveSchtasksExecutable(deps.environment),
        buildSchtasksLifecycleArgs(action, taskName),
    );
}

export async function startWindowsTunnelTask(
    taskName: string,
    dependencies: WindowsTunnelLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    return runLifecycleAction('start', taskName, dependencies);
}

export async function stopWindowsTunnelTask(
    taskName: string,
    dependencies: WindowsTunnelLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    return runLifecycleAction('stop', taskName, dependencies);
}

export async function uninstallWindowsTunnelTask(
    taskName: string,
    dependencies: WindowsTunnelLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    return runLifecycleAction('uninstall', taskName, dependencies);
}
