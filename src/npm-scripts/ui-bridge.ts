import { stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
    installWindowsUiBridgeTask,
    startWindowsUiBridgeTask,
    stopWindowsUiBridgeTask,
    uninstallWindowsUiBridgeTask,
    type InstallWindowsUiBridgeTaskOptions,
} from '../platform/windows/ui-bridge-lifecycle.js';
import type { RunExecutableResult } from '../platform/windows/scheduled-task.js';

export const DEFAULT_WINDOWS_UI_BRIDGE_TASK_NAME = 'JameDesktopCommander UI Bridge';

type InstallTask = (
    options: InstallWindowsUiBridgeTaskOptions & { replaceExisting: boolean },
) => Promise<RunExecutableResult>;

export interface WindowsUiBridgeCommandDependencies {
    platform?: NodeJS.Platform;
    currentUserId?: () => string;
    ensureFile?: (filePath: string) => Promise<void>;
    installTask?: InstallTask;
    startTask?: (taskName: string) => Promise<RunExecutableResult>;
    stopTask?: (taskName: string) => Promise<RunExecutableResult>;
    uninstallTask?: (taskName: string) => Promise<RunExecutableResult>;
}

export interface WindowsUiBridgeCommandResult {
    action: 'install' | 'start' | 'stop' | 'uninstall';
    taskName: string;
}

interface InstallArguments {
    bridgeExe: string;
    force: boolean;
}

function requireWindows(platform: NodeJS.Platform): void {
    if (platform !== 'win32') {
        throw new Error('JameDesktopCommander UI bridge lifecycle is supported only on Windows.');
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
    let bridgeExe: string | undefined;
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

        if (option === '--bridge-exe') {
            if (bridgeExe !== undefined) {
                throw new Error('--bridge-exe may be specified only once.');
            }
            const parsed = readRequiredOption(args, index, option);
            bridgeExe = parsed.value;
            index = parsed.nextIndex;
            continue;
        }

        throw new Error(`Unknown option for UI bridge install: ${option}`);
    }

    if (bridgeExe === undefined) {
        throw new Error('--bridge-exe is required for UI bridge install.');
    }

    return {
        bridgeExe: requireAbsoluteWindowsPath('--bridge-exe', bridgeExe),
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

async function ensureExistingFile(filePath: string): Promise<void> {
    const fileStat = await stat(filePath);
    if (!fileStat.isFile()) {
        throw new Error(`UI bridge executable is not a file: ${filePath}`);
    }
}

function resolveDependencies(
    dependencies: WindowsUiBridgeCommandDependencies,
): Required<WindowsUiBridgeCommandDependencies> {
    return {
        platform: dependencies.platform ?? process.platform,
        currentUserId: dependencies.currentUserId ?? resolveCurrentUserId,
        ensureFile: dependencies.ensureFile ?? ensureExistingFile,
        installTask:
            dependencies.installTask ??
            ((options) => installWindowsUiBridgeTask(options)),
        startTask:
            dependencies.startTask ??
            ((taskName) => startWindowsUiBridgeTask(taskName)),
        stopTask:
            dependencies.stopTask ??
            ((taskName) => stopWindowsUiBridgeTask(taskName)),
        uninstallTask:
            dependencies.uninstallTask ??
            ((taskName) => uninstallWindowsUiBridgeTask(taskName)),
    };
}

export async function runWindowsUiBridgeCommand(
    args: readonly string[],
    dependencies: WindowsUiBridgeCommandDependencies = {},
): Promise<WindowsUiBridgeCommandResult> {
    const deps = resolveDependencies(dependencies);
    requireWindows(deps.platform);

    const [action, ...actionArgs] = args;
    if (!action) {
        throw new Error('UI bridge action is required: install, start, stop, or uninstall.');
    }

    const taskName = DEFAULT_WINDOWS_UI_BRIDGE_TASK_NAME;

    switch (action) {
        case 'install': {
            const options = parseInstallArguments(actionArgs);
            await deps.ensureFile(options.bridgeExe);
            await deps.installTask({
                taskName,
                replaceExisting: options.force,
                task: {
                    author: deps.currentUserId(),
                    executable: options.bridgeExe,
                },
            });
            return { action, taskName };
        }
        case 'start':
        case 'stop':
        case 'uninstall': {
            if (actionArgs.length > 0) {
                throw new Error(`UI bridge ${action} does not accept additional arguments.`);
            }

            if (action === 'start') {
                await deps.startTask(taskName);
            } else if (action === 'stop') {
                await deps.stopTask(taskName);
            } else {
                await deps.uninstallTask(taskName);
            }
            return { action, taskName };
        }
        default:
            throw new Error(`Unknown UI bridge action: ${action}`);
    }
}

export function formatWindowsUiBridgeCommandResult(
    result: WindowsUiBridgeCommandResult,
): string {
    switch (result.action) {
        case 'install':
            return `Installed Windows UI bridge task "${result.taskName}".`;
        case 'start':
            return `Started Windows UI bridge task "${result.taskName}".`;
        case 'stop':
            return `Stopped Windows UI bridge task "${result.taskName}".`;
        case 'uninstall':
            return `Uninstalled Windows UI bridge task "${result.taskName}".`;
    }
}

function printUiBridgeHelp(): void {
    console.log(`JameDesktopCommander Windows UI bridge lifecycle

Usage:
  desktop-commander ui-bridge install --bridge-exe <absolute-path> [--force]
  desktop-commander ui-bridge start
  desktop-commander ui-bridge stop
  desktop-commander ui-bridge uninstall

Notes:
  The bridge executable must be a durable absolute Windows path.
  Existing tasks are not replaced unless --force is supplied.
  The task runs only in the owning user's interactive session.`);
}

export async function runUiBridge(
    args: readonly string[] = process.argv.slice(3),
): Promise<void> {
    if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
        printUiBridgeHelp();
        return;
    }

    try {
        const result = await runWindowsUiBridgeCommand(args);
        console.log(formatWindowsUiBridgeCommandResult(result));
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`UI bridge command failed: ${message}`);
        process.exitCode = 1;
    }
}
