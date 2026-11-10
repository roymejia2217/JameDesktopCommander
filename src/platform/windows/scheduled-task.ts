import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import koffi from 'koffi';

export type WindowsScheduledTaskLifecycleAction = 'start' | 'stop' | 'enable' | 'disable' | 'uninstall';

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

type GetSystemDirectoryW = (buffer: Buffer, capacity: number) => number;
let getSystemDirectoryW: GetSystemDirectoryW | undefined;

function nativeWindowsSystemDirectory(): string {
    // Query Windows, never the caller's SystemRoot or PATH.
    if (!getSystemDirectoryW) {
        getSystemDirectoryW = koffi.load('kernel32.dll').func(
            '__stdcall', 'GetSystemDirectoryW', 'uint32_t',
            ['uint16_t *', 'uint32_t'],
        ) as GetSystemDirectoryW;
    }
    const capacity = 32768; // Windows maximum extended path, in UTF-16 units.
    const buffer = Buffer.alloc(capacity * 2);
    const length = getSystemDirectoryW(buffer, capacity);
    if (!Number.isInteger(length) || length === 0 || length >= capacity) {
        throw new Error('Windows system directory could not be determined.');
    }
    const observed = buffer.toString('utf16le', 0, length * 2);
    if (!/^[A-Za-z]:\\/.test(observed) ||
        observed.includes('\0') ||
        path.win32.normalize(observed) !== observed) {
        throw new Error('Windows returned an invalid system directory.');
    }
    return observed.replace(/\\system32$/i, '\\System32');
}

/** Only fixed OS utilities; no caller-supplied path or executable names. */
export type WindowsSystemTool = 'schtasks' | 'powershell' | 'taskkill';

export function resolveWindowsSystemTool(
    tool: WindowsSystemTool,
    environment: Record<string, string | undefined> = process.env,
): string {
    // On actual Windows, SystemRoot, PATH and dependency overrides are untrusted.
    // Non-Windows fallback exists only for cross-platform synthetic fixtures.
    let systemDirectory: string;
    if (process.platform === 'win32') {
        systemDirectory = nativeWindowsSystemDirectory();
    } else {
        const systemRoot = environment.SystemRoot?.trim();
        if (!systemRoot || !path.win32.isAbsolute(systemRoot)) {
            throw new Error('SystemRoot must contain an absolute Windows path.');
        }
        systemDirectory = path.win32.join(systemRoot, 'System32');
    }
    switch (tool) {
        case 'schtasks':
            return path.win32.join(systemDirectory, 'schtasks.exe');
        case 'taskkill':
            return path.win32.join(systemDirectory, 'taskkill.exe');
        case 'powershell':
            return path.win32.join(
                systemDirectory, 'WindowsPowerShell', 'v1.0', 'powershell.exe',
            );
        default: {
            const exhaustiveCheck: never = tool;
            throw new Error(`Unsupported Windows system tool: ${exhaustiveCheck}`);
        }
    }
}

export function resolveSchtasksExecutable(
    environment: Record<string, string | undefined> = process.env,
): string {
    return resolveWindowsSystemTool('schtasks', environment);
}

export function buildSchtasksQueryXmlArgs(taskName: string): string[] {
    return ['/Query', '/TN', requireTaskName(taskName), '/XML'];
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
        case 'enable':
            return ['/Change', '/TN', normalizedTaskName, '/ENABLE'];
        case 'disable':
            return ['/Change', '/TN', normalizedTaskName, '/DISABLE'];
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
