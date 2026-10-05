import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export type WindowsScheduledTaskLifecycleAction = 'start' | 'stop' | 'uninstall';

export interface RunExecutableResult {
    stdout: string;
    stderr: string;
}

export type RunExecutable = (
    executable: string,
    args: readonly string[],
) => Promise<RunExecutableResult>;

export interface WindowsScheduledTaskDependencies {
    environment?: Record<string, string | undefined>;
    makeTempDirectory?: (prefix: string) => Promise<string>;
    writeFile?: (filePath: string, data: Buffer) => Promise<void>;
    removeDirectory?: (directory: string) => Promise<void>;
    runExecutable?: RunExecutable;
}

export interface InstallWindowsScheduledTaskOptions {
    taskName: string;
    taskXml: string;
    tempPrefix: string;
    replaceExisting?: boolean;
}

export function requireNonEmpty(label: string, value: string): string {
    const normalized = value.trim();
    if (!normalized) {
        throw new Error(`${label} must not be empty.`);
    }
    return normalized;
}

export function requireAbsoluteWindowsPath(label: string, value: string): string {
    const normalized = requireNonEmpty(label, value);
    if (!path.win32.isAbsolute(normalized)) {
        throw new Error(`${label} must be an absolute Windows path.`);
    }
    return path.win32.normalize(normalized);
}

export function escapeWindowsTaskXml(value: string): string {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

export function encodeWindowsTaskXml(xml: string): Buffer {
    const body = Buffer.from(xml, 'utf16le');
    return Buffer.concat([Buffer.from([0xff, 0xfe]), body]);
}

function requireTaskName(taskName: string): string {
    const normalized = requireNonEmpty('Task name', taskName);
    if (/[\0\r\n]/.test(normalized)) {
        throw new Error('Task name contains unsupported control characters.');
    }
    return normalized;
}

export function buildSchtasksCreateArgs(
    taskName: string,
    xmlPath: string,
    replaceExisting = true,
): string[] {
    const normalizedTaskName = requireTaskName(taskName);
    const normalizedXmlPath = requireAbsoluteWindowsPath('Task XML path', xmlPath);

    const args = [
        '/Create',
        '/TN',
        normalizedTaskName,
        '/XML',
        normalizedXmlPath,
    ];

    if (replaceExisting) {
        args.push('/F');
    }

    return args;
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
    action: WindowsScheduledTaskLifecycleAction,
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
    dependencies: WindowsScheduledTaskDependencies,
): Required<WindowsScheduledTaskDependencies> {
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

export async function installWindowsScheduledTask(
    options: InstallWindowsScheduledTaskOptions,
    dependencies: WindowsScheduledTaskDependencies = {},
): Promise<RunExecutableResult> {
    const taskName = requireTaskName(options.taskName);
    const taskXml = requireNonEmpty('Task XML', options.taskXml);
    const tempPrefix = requireNonEmpty('Task temp prefix', options.tempPrefix);
    const deps = resolveDependencies(dependencies);
    const schtasksExecutable = resolveSchtasksExecutable(deps.environment);
    const tempDirectory = await deps.makeTempDirectory(
        path.join(os.tmpdir(), tempPrefix),
    );
    const xmlPath = path.win32.join(tempDirectory, 'task.xml');

    try {
        await deps.writeFile(xmlPath, encodeWindowsTaskXml(taskXml));
        return await deps.runExecutable(
            schtasksExecutable,
            buildSchtasksCreateArgs(
                taskName,
                xmlPath,
                options.replaceExisting ?? true,
            ),
        );
    } finally {
        await deps.removeDirectory(tempDirectory);
    }
}

export async function runWindowsScheduledTaskAction(
    action: WindowsScheduledTaskLifecycleAction,
    taskName: string,
    dependencies: WindowsScheduledTaskDependencies = {},
): Promise<RunExecutableResult> {
    const deps = resolveDependencies(dependencies);
    return deps.runExecutable(
        resolveSchtasksExecutable(deps.environment),
        buildSchtasksLifecycleArgs(action, taskName),
    );
}
