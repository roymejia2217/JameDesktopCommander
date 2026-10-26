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
    isWindowsTunnelHealthReady,
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
import {
    readTunnelFunctionalDiagnostics,
    type TunnelFunctionalDiagnostics,
} from '../platform/windows/tunnel-functional-diagnostics.js';
import {
    readWindowsTunnelTaskEvents,
    type WindowsTunnelTaskEvents,
} from '../platform/windows/tunnel-task-events.js';

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
    diagnoseLocal?: (baseUrl: string) => Promise<TunnelFunctionalDiagnostics>;
    taskEvents?: (taskName: string) => Promise<WindowsTunnelTaskEvents>;
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
    }
    | {
        action: 'diagnose';
        taskName: string;
        diagnostics: TunnelFunctionalDiagnostics;
    }
    | {
        action: 'events';
        taskName: string;
        history: WindowsTunnelTaskEvents;
    };

interface InstallArguments {
    tunnelClientBin: string;
    profileDir: string;
    profile: string;
    force: boolean;
    recoverOnExit: boolean;
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
    let recoverOnExit = false;

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

        if (option === '--recover-on-exit') {
            if (recoverOnExit) {
                throw new Error('--recover-on-exit may be specified only once.');
            }
            recoverOnExit = true;
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
        recoverOnExit,
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
        diagnoseLocal:
            dependencies.diagnoseLocal ??
            ((baseUrl) => readTunnelFunctionalDiagnostics(baseUrl)),
        taskEvents:
            dependencies.taskEvents ??
            ((taskName) => readWindowsTunnelTaskEvents(taskName)),
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
        throw new Error('Tunnel action is required: install, start, stop, restart, status, diagnose, events, or uninstall.');
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
                    ...(options.recoverOnExit ? { recoveryIntervalMinutes: 5 } : {}),
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
        case 'diagnose': {
            if (actionArgs.length > 0) {
                throw new Error('Tunnel diagnose does not accept additional arguments.');
            }
            const state = await deps.statusTunnel(taskName);
            return { action, taskName,
                diagnostics: await deps.diagnoseLocal(state.health.baseUrl) };
        }
        case 'events': {
            if (actionArgs.length > 0) {
                throw new Error('Tunnel events does not accept additional arguments.');
            }
            // Does not depend on tunnel health, nor authorize any lifecycle action.
            return { action, taskName, history: await deps.taskEvents(taskName) };
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
        case 'diagnose':
            return JSON.stringify(result.diagnostics, null, 2);
        case 'events':
            return JSON.stringify(result.history, null, 2);
    }
}

function printTunnelHelp(): void {
    console.log(`Desktop Commander Secure MCP Tunnel lifecycle

Usage:
  desktop-commander tunnel install --tunnel-client-bin <absolute-path> --profile-dir <absolute-path> --profile <name> [--force] [--recover-on-exit]
  desktop-commander tunnel start
  desktop-commander tunnel stop
  desktop-commander tunnel restart
  desktop-commander tunnel status
  desktop-commander tunnel diagnose
  desktop-commander tunnel events
  desktop-commander tunnel uninstall

Notes:
  install runs the official tunnel-client doctor before registering the task.
  --recover-on-exit opts in to native Task Scheduler five-minute repetitions on unexpected process exit, including exit code 0.
  stop first disables the task to preserve intentional operator STOP; start re-enables it.
  restart re-registers and launches an external Windows Task Scheduler supervisor so it survives the tunnel process tree.
  events reads only bounded, sanitized Task Scheduler metadata, even when the tunnel is offline; it never authorizes a restart.
  Existing tunnel tasks are not replaced unless --force is supplied.
  Secrets remain owned by tunnel-client profiles via env: or file: references.`);
}

export async function runTunnel(
    args: readonly string[] = process.argv.slice(3),
    dependencies: WindowsTunnelCommandDependencies = {},
): Promise<void> {
    const platform = dependencies.platform ?? process.platform;
    if (platform === 'linux') {
        if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
            console.log('Linux tunnel: doctor|install --tunnel-client-bin <absolute> --profile-dir <absolute> --profile <name> | start | stop | restart | status | uninstall');
            return;
        }
        try {
            // Import only on Linux: Windows lifecycle and existing tests remain untouched.
            const { runLinuxTunnelCommand } = await import('../platform/linux/tunnel-lifecycle.js');
            const result = await runLinuxTunnelCommand(args, { platform });
            console.log(JSON.stringify(result, null, 2));
            if (result.action === 'status' &&
                (!result.status?.active || !result.status.enabled || !result.status.healthy ||
                 !result.status.controlPlanePoll)) {
                process.exitCode = 1;
            }
        } catch (error) {
            console.error('Linux tunnel command failed: ' +
                (error instanceof Error ? error.message : 'Unknown error'));
            process.exitCode = 1;
        }
        return;
    }
    if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
        printTunnelHelp();
        return;
    }

    try {
        const result = await runWindowsTunnelCommand(args, dependencies);
        console.log(formatWindowsTunnelCommandResult(result));
        if (
            result.action === 'status' &&
            !isWindowsTunnelHealthReady(result.status.health)
        ) {
            process.exitCode = 1;
        }
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`Tunnel command failed: ${message}`);
        process.exitCode = 1;
    }
}
