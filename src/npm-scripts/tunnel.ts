import { execFile } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    installWindowsTunnelTask,
    startWindowsTunnelTask,
    stopWindowsTunnelTask,
    uninstallWindowsTunnelTask,
    type InstallWindowsTunnelTaskOptions,
    type RunExecutable,
    type RunExecutableResult,
} from '../platform/windows/tunnel-lifecycle.js';
import {
    getWindowsTunnelStatus,
    type WindowsTunnelStatus,
} from '../platform/windows/tunnel-status.js';
import {
    installWindowsTunnelRestartSupervisorTask,
    startWindowsTunnelRestartSupervisorTask,
    uninstallWindowsTunnelRestartSupervisorTask,
    type InstallWindowsTunnelRestartSupervisorTaskOptions,
} from '../platform/windows/tunnel-restart-lifecycle.js';
import {
    DEFAULT_WINDOWS_TUNNEL_RESTART_SUPERVISOR_TASK_NAME,
} from '../platform/windows/tunnel-restart-supervisor-task.js';

export const DEFAULT_WINDOWS_TUNNEL_TASK_NAME = 'Desktop Commander Windows Tunnel';

const PROFILE_NAME_PATTERN = /^[A-Za-z0-9._-]+$/;

type InstallTask = (
    options: InstallWindowsTunnelTaskOptions & { replaceExisting: boolean },
) => Promise<RunExecutableResult>;

type InstallRestartSupervisorTask = (
    options: InstallWindowsTunnelRestartSupervisorTaskOptions & {
        replaceExisting: boolean;
    },
) => Promise<RunExecutableResult>;

export interface WindowsTunnelCommandDependencies {
    platform?: NodeJS.Platform;
    currentUserId?: () => string;
    runExecutable?: RunExecutable;
    installTask?: InstallTask;
    startTask?: (taskName: string) => Promise<RunExecutableResult>;
    stopTask?: (taskName: string) => Promise<RunExecutableResult>;
    uninstallTask?: (taskName: string) => Promise<RunExecutableResult>;
    statusTunnel?: (taskName: string) => Promise<WindowsTunnelStatus>;
    nodeExecutable?: () => string;
    restartWorkerScript?: () => string;
    installRestartSupervisorTask?: InstallRestartSupervisorTask;
    startRestartSupervisorTask?: (
        taskName: string,
    ) => Promise<RunExecutableResult>;
    uninstallRestartSupervisorTask?: (
        taskName: string,
    ) => Promise<RunExecutableResult>;
}

export type WindowsTunnelCommandResult =
    | {
        action: 'install' | 'start' | 'stop' | 'uninstall';
        taskName: string;
    }
    | {
        action: 'restart';
        taskName: string;
        supervisorTaskName: string;
    }
    | {
        action: 'status';
        taskName: string;
        status: WindowsTunnelStatus;
    };

interface InstallArguments {
    tunnelClientBin: string;
    profileDir: string;
    profile: string;
    force: boolean;
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

function requireWindows(platform: NodeJS.Platform): void {
    if (platform !== 'win32') {
        throw new Error('Desktop Commander tunnel lifecycle is supported only on Windows.');
    }
}

function requireAbsoluteWindowsPath(label: string, value: string): string {
    const normalized = value.trim();
    if (!normalized) {
        throw new Error(`${label} must not be empty.`);
    }
    if (!path.win32.isAbsolute(normalized)) {
        throw new Error(`${label} must be an absolute Windows path.`);
    }
    return path.win32.normalize(normalized);
}

function requireProfileName(value: string): string {
    const normalized = value.trim();
    if (!normalized) {
        throw new Error('--profile must not be empty.');
    }
    if (!PROFILE_NAME_PATTERN.test(normalized)) {
        throw new Error('--profile may contain only letters, digits, dot, underscore, and hyphen.');
    }
    return normalized;
}

function readRequiredOption(
    args: readonly string[],
    index: number,
    option: string,
): { value: string; nextIndex: number } {
    const value = args[index + 1];
    if (!value || value.startsWith('--')) {
        throw new Error(`${option} requires a value.`);
    }
    return { value, nextIndex: index + 2 };
}

function parseInstallArguments(args: readonly string[]): InstallArguments {
    let tunnelClientBin: string | undefined;
    let profileDir: string | undefined;
    let profile: string | undefined;
    let force = false;

    for (let index = 0; index < args.length;) {
        const option = args[index];

        if (option === '--force') {
            if (force) {
                throw new Error('--force may be specified only once.');
            }
            force = true;
            index += 1;
            continue;
        }

        if (
            option === '--tunnel-client-bin' ||
            option === '--profile-dir' ||
            option === '--profile'
        ) {
            const parsed = readRequiredOption(args, index, option);
            switch (option) {
                case '--tunnel-client-bin':
                    if (tunnelClientBin !== undefined) {
                        throw new Error('--tunnel-client-bin may be specified only once.');
                    }
                    tunnelClientBin = parsed.value;
                    break;
                case '--profile-dir':
                    if (profileDir !== undefined) {
                        throw new Error('--profile-dir may be specified only once.');
                    }
                    profileDir = parsed.value;
                    break;
                case '--profile':
                    if (profile !== undefined) {
                        throw new Error('--profile may be specified only once.');
                    }
                    profile = parsed.value;
                    break;
            }
            index = parsed.nextIndex;
            continue;
        }

        throw new Error(`Unknown option for tunnel install: ${option}`);
    }

    if (tunnelClientBin === undefined) {
        throw new Error('--tunnel-client-bin is required for tunnel install.');
    }
    if (profileDir === undefined) {
        throw new Error('--profile-dir is required for tunnel install.');
    }
    if (profile === undefined) {
        throw new Error('--profile is required for tunnel install.');
    }

    return {
        tunnelClientBin: requireAbsoluteWindowsPath(
            '--tunnel-client-bin',
            tunnelClientBin,
        ),
        profileDir: requireAbsoluteWindowsPath('--profile-dir', profileDir),
        profile: requireProfileName(profile),
        force,
    };
}

function resolveCurrentUserId(): string {
    const username = (process.env.USERNAME ?? os.userInfo().username).trim();
    if (!username) {
        throw new Error('Unable to determine the current Windows user.');
    }

    const domain = process.env.USERDOMAIN?.trim();
    return domain ? `${domain}\\${username}` : username;
}

function resolveRestartWorkerScript(): string {
    return path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        'tunnel-restart-worker.js',
    );
}

function resolveDependencies(
    dependencies: WindowsTunnelCommandDependencies,
): Required<WindowsTunnelCommandDependencies> {
    return {
        platform: dependencies.platform ?? process.platform,
        currentUserId: dependencies.currentUserId ?? resolveCurrentUserId,
        runExecutable: dependencies.runExecutable ?? defaultRunExecutable,
        installTask:
            dependencies.installTask ??
            ((options) => installWindowsTunnelTask(options)),
        startTask:
            dependencies.startTask ??
            ((taskName) => startWindowsTunnelTask(taskName)),
        stopTask:
            dependencies.stopTask ??
            ((taskName) => stopWindowsTunnelTask(taskName)),
        uninstallTask:
            dependencies.uninstallTask ??
            ((taskName) => uninstallWindowsTunnelTask(taskName)),
        statusTunnel:
            dependencies.statusTunnel ??
            ((taskName) => getWindowsTunnelStatus(taskName)),
        nodeExecutable:
            dependencies.nodeExecutable ??
            (() => process.execPath),
        restartWorkerScript:
            dependencies.restartWorkerScript ??
            resolveRestartWorkerScript,
        installRestartSupervisorTask:
            dependencies.installRestartSupervisorTask ??
            ((options) =>
                installWindowsTunnelRestartSupervisorTask(options)),
        startRestartSupervisorTask:
            dependencies.startRestartSupervisorTask ??
            ((taskName) =>
                startWindowsTunnelRestartSupervisorTask(taskName)),
        uninstallRestartSupervisorTask:
            dependencies.uninstallRestartSupervisorTask ??
            ((taskName) =>
                uninstallWindowsTunnelRestartSupervisorTask(taskName)),
    };
}

export async function runWindowsTunnelCommand(
    args: readonly string[],
    dependencies: WindowsTunnelCommandDependencies = {},
): Promise<WindowsTunnelCommandResult> {
    const deps = resolveDependencies(dependencies);
    requireWindows(deps.platform);

    const [action, ...actionArgs] = args;
    if (!action) {
        throw new Error('Tunnel action is required: install, start, stop, restart, status, or uninstall.');
    }

    const taskName = DEFAULT_WINDOWS_TUNNEL_TASK_NAME;

    switch (action) {
        case 'install': {
            const options = parseInstallArguments(actionArgs);

            await deps.runExecutable(options.tunnelClientBin, [
                'doctor',
                '--profile-dir',
                options.profileDir,
                '--profile',
                options.profile,
                '--explain',
            ]);

            const author = deps.currentUserId();
            await deps.installTask({
                taskName,
                replaceExisting: options.force,
                task: {
                    author,
                    executable: options.tunnelClientBin,
                    profileDir: options.profileDir,
                    profileName: options.profile,
                },
            });

            await deps.installRestartSupervisorTask({
                taskName:
                    DEFAULT_WINDOWS_TUNNEL_RESTART_SUPERVISOR_TASK_NAME,
                replaceExisting: options.force,
                task: {
                    author,
                    nodeExecutable: deps.nodeExecutable(),
                    workerScript: deps.restartWorkerScript(),
                    tunnelTaskName: taskName,
                },
            });

            return { action, taskName };
        }
        case 'restart': {
            if (actionArgs.length > 0) {
                throw new Error('Tunnel restart does not accept additional arguments.');
            }

            await deps.installRestartSupervisorTask({
                taskName:
                    DEFAULT_WINDOWS_TUNNEL_RESTART_SUPERVISOR_TASK_NAME,
                replaceExisting: true,
                task: {
                    author: deps.currentUserId(),
                    nodeExecutable: deps.nodeExecutable(),
                    workerScript: deps.restartWorkerScript(),
                    tunnelTaskName: taskName,
                },
            });
            await deps.startRestartSupervisorTask(
                DEFAULT_WINDOWS_TUNNEL_RESTART_SUPERVISOR_TASK_NAME,
            );
            return {
                action,
                taskName,
                supervisorTaskName:
                    DEFAULT_WINDOWS_TUNNEL_RESTART_SUPERVISOR_TASK_NAME,
            };
        }
        case 'status': {
            if (actionArgs.length > 0) {
                throw new Error('Tunnel status does not accept additional arguments.');
            }
            return {
                action,
                taskName,
                status: await deps.statusTunnel(taskName),
            };
        }
        case 'start':
        case 'stop':
        case 'uninstall': {
            if (actionArgs.length > 0) {
                throw new Error(`Tunnel ${action} does not accept additional arguments.`);
            }

            if (action === 'start') {
                await deps.startTask(taskName);
            } else if (action === 'stop') {
                await deps.stopTask(taskName);
            } else {
                await deps.uninstallRestartSupervisorTask(
                    DEFAULT_WINDOWS_TUNNEL_RESTART_SUPERVISOR_TASK_NAME,
                );
                await deps.uninstallTask(taskName);
            }

            return { action, taskName };
        }
        default:
            throw new Error(`Unknown tunnel action: ${action}`);
    }
}

export function formatWindowsTunnelCommandResult(
    result: WindowsTunnelCommandResult,
): string {
    switch (result.action) {
        case 'install':
            return `Installed Windows tunnel task "${result.taskName}".`;
        case 'start':
            return `Started Windows tunnel task "${result.taskName}".`;
        case 'stop':
            return `Stopped Windows tunnel task "${result.taskName}".`;
        case 'restart':
            return `Scheduled Windows tunnel restart through supervisor "${result.supervisorTaskName}".`;
        case 'uninstall':
            return `Uninstalled Windows tunnel task "${result.taskName}".`;
        case 'status':
            return JSON.stringify(result.status, null, 2);
    }
}

function printTunnelHelp(): void {
    console.log(`Desktop Commander Secure MCP Tunnel lifecycle

Usage:
  desktop-commander tunnel install --tunnel-client-bin <absolute-path> --profile-dir <absolute-path> --profile <name> [--force]
  desktop-commander tunnel start
  desktop-commander tunnel stop
  desktop-commander tunnel restart
  desktop-commander tunnel status
  desktop-commander tunnel uninstall

Notes:
  install runs the official tunnel-client doctor before registering the task.
  restart re-registers and launches an external Windows Task Scheduler supervisor so it survives the tunnel process tree.
  Existing tunnel tasks are not replaced unless --force is supplied.
  Secrets remain owned by tunnel-client profiles via env: or file: references.`);
}

export async function runTunnel(args: readonly string[] = process.argv.slice(3)): Promise<void> {
    if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
        printTunnelHelp();
        return;
    }

    try {
        const result = await runWindowsTunnelCommand(args);
        console.log(formatWindowsTunnelCommandResult(result));
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`Tunnel command failed: ${message}`);
        process.exitCode = 1;
    }
}
