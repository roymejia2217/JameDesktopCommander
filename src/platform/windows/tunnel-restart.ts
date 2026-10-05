import { execFile } from 'node:child_process';
import path from 'node:path';

import {
    resolveSchtasksExecutable,
    type RunExecutable,
    type RunExecutableResult,
} from './scheduled-task.js';
import {
    startWindowsTunnelTask,
    stopWindowsTunnelTask,
} from './tunnel-lifecycle.js';
import {
    getWindowsTunnelRegistration,
    getWindowsTunnelStatus,
    type WindowsTunnelRegistration,
    type WindowsTunnelStatus,
} from './tunnel-status.js';
import { buildWindowsTunnelRunArguments } from './tunnel-task.js';

export interface WindowsProcessRecord {
    processId: number;
    parentProcessId: number;
    executablePath: string | null;
    commandLine: string | null;
    creationDate: string;
}

export interface CapturedTunnelProcessTree {
    root: WindowsProcessRecord | null;
    descendants: WindowsProcessRecord[];
}

export interface WindowsTunnelRestartResult {
    oldRootPid: number | null;
    newRootPid: number;
    health: WindowsTunnelStatus['health'];
}

export interface WindowsTunnelRestartDependencies {
    environment?: Record<string, string | undefined>;
    runExecutable?: RunExecutable;
    getRegistration?: (
        taskName: string,
    ) => Promise<WindowsTunnelRegistration>;
    getStatus?: (taskName: string) => Promise<WindowsTunnelStatus>;
    listProcesses?: () => Promise<WindowsProcessRecord[]>;
    stopTask?: (taskName: string) => Promise<RunExecutableResult>;
    startTask?: (taskName: string) => Promise<RunExecutableResult>;
    terminateProcessTree?: (pid: number) => Promise<RunExecutableResult>;
    sleep?: (milliseconds: number) => Promise<void>;
    stopGraceAttempts?: number;
    stopVerifyAttempts?: number;
    startAttempts?: number;
    healthAttempts?: number;
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

function requireSystemRoot(
    environment: Record<string, string | undefined>,
): string {
    const systemRoot = environment.SystemRoot?.trim();
    if (!systemRoot || !path.win32.isAbsolute(systemRoot)) {
        throw new Error('SystemRoot must contain an absolute Windows path.');
    }
    return path.win32.normalize(systemRoot);
}

function resolvePowerShellExecutable(
    environment: Record<string, string | undefined>,
): string {
    return path.win32.join(
        requireSystemRoot(environment),
        'System32',
        'WindowsPowerShell',
        'v1.0',
        'powershell.exe',
    );
}

function resolveTaskkillExecutable(
    environment: Record<string, string | undefined>,
): string {
    return path.win32.join(
        requireSystemRoot(environment),
        'System32',
        'taskkill.exe',
    );
}

function normalizeWindowsPath(value: string): string {
    return path.win32.normalize(value).toLowerCase();
}

function sameCapturedProcess(
    expected: WindowsProcessRecord,
    current: WindowsProcessRecord,
): boolean {
    return (
        expected.processId === current.processId &&
        expected.creationDate === current.creationDate
    );
}

function allCapturedProcesses(
    tree: CapturedTunnelProcessTree,
): WindowsProcessRecord[] {
    return tree.root ? [tree.root, ...tree.descendants] : [];
}

function survivingCapturedProcesses(
    tree: CapturedTunnelProcessTree,
    current: WindowsProcessRecord[],
): WindowsProcessRecord[] {
    return allCapturedProcesses(tree).filter((captured) =>
        current.some((process) => sameCapturedProcess(captured, process)),
    );
}

export function captureOwnedTunnelProcessTree(
    registration: WindowsTunnelRegistration,
    processes: WindowsProcessRecord[],
): CapturedTunnelProcessTree {
    const expectedExecutable = normalizeWindowsPath(
        registration.task.executable,
    );
    const expectedArguments = buildWindowsTunnelRunArguments(
        registration.task.profileDir,
        registration.task.profileName,
    ).toLowerCase();

    const roots = processes.filter((process) => {
        if (!process.executablePath || !process.commandLine) {
            return false;
        }
        return (
            normalizeWindowsPath(process.executablePath) ===
                expectedExecutable &&
            process.commandLine.toLowerCase().includes(expectedArguments)
        );
    });

    if (roots.length > 1) {
        throw new Error(
            'Multiple tunnel-client processes match the registered tunnel task.',
        );
    }
    if (roots.length === 0) {
        return { root: null, descendants: [] };
    }

    const root = roots[0];
    const descendants: WindowsProcessRecord[] = [];
    const queue = [root.processId];

    while (queue.length > 0) {
        const parent = queue.shift()!;
        for (const process of processes) {
            if (process.parentProcessId !== parent) {
                continue;
            }
            descendants.push(process);
            queue.push(process.processId);
        }
    }

    return { root, descendants };
}

function parseWindowsProcessList(rawJson: string): WindowsProcessRecord[] {
    let parsed: unknown;
    try {
        parsed = JSON.parse(rawJson);
    } catch {
        throw new Error('Windows process inventory is not valid JSON.');
    }

    const values = Array.isArray(parsed) ? parsed : [parsed];
    return values.map((value) => {
        if (typeof value !== 'object' || value === null) {
            throw new Error('Windows process inventory contains invalid data.');
        }
        const record = value as Record<string, unknown>;
        const processId = Number(record.processId);
        const parentProcessId = Number(record.parentProcessId);
        const creationDate =
            typeof record.creationDate === 'string'
                ? record.creationDate
                : '';
        if (
            !Number.isInteger(processId) ||
            processId < 0 ||
            !Number.isInteger(parentProcessId) ||
            parentProcessId < 0 ||
            !creationDate
        ) {
            throw new Error('Windows process inventory contains invalid identity fields.');
        }
        return {
            processId,
            parentProcessId,
            executablePath:
                typeof record.executablePath === 'string'
                    ? record.executablePath
                    : null,
            commandLine:
                typeof record.commandLine === 'string'
                    ? record.commandLine
                    : null,
            creationDate,
        };
    });
}

export function buildWindowsProcessInventoryPowerShell(): string {
    return [
        "$ErrorActionPreference='Stop'",
        '$items=@(Get-CimInstance Win32_Process | ForEach-Object {',
        '  [pscustomobject]@{',
        '    processId=[int]$_.ProcessId',
        '    parentProcessId=[int]$_.ParentProcessId',
        '    executablePath=$_.ExecutablePath',
        '    commandLine=$_.CommandLine',
        "    creationDate=if($_.CreationDate){$_.CreationDate.ToUniversalTime().ToString('o')}else{''}",
        '  }',
        '})',
        '$items | ConvertTo-Json -Compress',
    ].join('\r\n');
}

async function listWindowsProcesses(
    environment: Record<string, string | undefined>,
    runExecutable: RunExecutable,
): Promise<WindowsProcessRecord[]> {
    const script = buildWindowsProcessInventoryPowerShell();
    const encodedCommand = Buffer.from(script, 'utf16le').toString('base64');
    const result = await runExecutable(
        resolvePowerShellExecutable(environment),
        [
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-EncodedCommand',
            encodedCommand,
        ],
    );
    return parseWindowsProcessList(result.stdout);
}

function resolveDependencies(
    dependencies: WindowsTunnelRestartDependencies,
): Required<WindowsTunnelRestartDependencies> {
    const environment = dependencies.environment ?? process.env;
    const runExecutable =
        dependencies.runExecutable ?? defaultRunExecutable;

    return {
        environment,
        runExecutable,
        getRegistration:
            dependencies.getRegistration ??
            ((taskName) =>
                getWindowsTunnelRegistration(taskName, {
                    environment,
                    runExecutable,
                })),
        getStatus:
            dependencies.getStatus ??
            ((taskName) =>
                getWindowsTunnelStatus(taskName, {
                    environment,
                    runExecutable,
                })),
        listProcesses:
            dependencies.listProcesses ??
            (() => listWindowsProcesses(environment, runExecutable)),
        stopTask:
            dependencies.stopTask ??
            ((taskName) =>
                stopWindowsTunnelTask(taskName, {
                    environment,
                    runExecutable,
                })),
        startTask:
            dependencies.startTask ??
            ((taskName) =>
                startWindowsTunnelTask(taskName, {
                    environment,
                    runExecutable,
                })),
        terminateProcessTree:
            dependencies.terminateProcessTree ??
            ((pid) =>
                runExecutable(resolveTaskkillExecutable(environment), [
                    '/PID',
                    String(pid),
                    '/T',
                    '/F',
                ])),
        sleep:
            dependencies.sleep ??
            ((milliseconds) =>
                new Promise((resolve) => setTimeout(resolve, milliseconds))),
        stopGraceAttempts: dependencies.stopGraceAttempts ?? 4,
        stopVerifyAttempts: dependencies.stopVerifyAttempts ?? 20,
        startAttempts: dependencies.startAttempts ?? 90,
        healthAttempts: dependencies.healthAttempts ?? 45,
    };
}

export async function restartWindowsTunnel(
    taskName: string,
    dependencies: WindowsTunnelRestartDependencies = {},
): Promise<WindowsTunnelRestartResult> {
    const deps = resolveDependencies(dependencies);
    const registration = await deps.getRegistration(taskName);
    const initialProcesses = await deps.listProcesses();
    const captured = captureOwnedTunnelProcessTree(
        registration,
        initialProcesses,
    );
    const oldRootPid = captured.root?.processId ?? null;

    if (captured.root) {
        await deps.stopTask(taskName);

        let currentProcesses = initialProcesses;
        for (let attempt = 0; attempt < deps.stopGraceAttempts; attempt += 1) {
            await deps.sleep(250);
            currentProcesses = await deps.listProcesses();
            if (survivingCapturedProcesses(captured, currentProcesses).length === 0) {
                break;
            }
        }

        let survivors = survivingCapturedProcesses(
            captured,
            currentProcesses,
        );
        if (survivors.length > 0) {
            const survivingPids = new Set(
                survivors.map((process) => process.processId),
            );
            const killTargets = survivors.filter(
                (process) => !survivingPids.has(process.parentProcessId),
            );

            for (const target of killTargets) {
                try {
                    await deps.terminateProcessTree(target.processId);
                } catch (error) {
                    const afterFailure = await deps.listProcesses();
                    const targetStillAlive = afterFailure.some((process) =>
                        sameCapturedProcess(target, process),
                    );
                    if (targetStillAlive) {
                        throw error;
                    }
                }
            }
        }

        let stopped = false;
        for (let attempt = 0; attempt < deps.stopVerifyAttempts; attempt += 1) {
            const current = await deps.listProcesses();
            if (survivingCapturedProcesses(captured, current).length === 0) {
                stopped = true;
                break;
            }
            await deps.sleep(250);
        }
        if (!stopped) {
            throw new Error(
                'The previous tunnel process tree did not terminate completely.',
            );
        }
    }

    await deps.startTask(taskName);

    let newRoot: WindowsProcessRecord | null = null;
    for (let attempt = 0; attempt < deps.startAttempts; attempt += 1) {
        const current = await deps.listProcesses();
        const currentTree = captureOwnedTunnelProcessTree(
            registration,
            current,
        );
        if (
            currentTree.root &&
            (!captured.root ||
                !sameCapturedProcess(captured.root, currentTree.root))
        ) {
            newRoot = currentTree.root;
            break;
        }
        await deps.sleep(500);
    }
    if (!newRoot) {
        throw new Error('A new tunnel-client process did not start.');
    }

    let lastHealthError: unknown;
    for (let attempt = 0; attempt < deps.healthAttempts; attempt += 1) {
        try {
            const status = await deps.getStatus(taskName);
            if (
                status.health.result === 'ok' &&
                status.health.live &&
                status.health.ready &&
                status.health.controlPlanePoll
            ) {
                return {
                    oldRootPid,
                    newRootPid: newRoot.processId,
                    health: status.health,
                };
            }
        } catch (error) {
            lastHealthError = error;
        }
        await deps.sleep(1000);
    }

    const detail =
        lastHealthError instanceof Error
            ? ` Last health error: ${lastHealthError.message}`
            : '';
    throw new Error(
        `The restarted tunnel did not reach full readiness.${detail}`,
    );
}
