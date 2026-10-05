import { buildWindowsTunnelTaskXml, type WindowsTunnelTaskOptions } from './tunnel-task.js';
import {
    buildSchtasksLifecycleArgs,
    installWindowsScheduledTask,
    resolveSchtasksExecutable,
    runWindowsScheduledTaskAction,
    type RunExecutable,
    type RunExecutableResult,
    type WindowsScheduledTaskDependencies,
} from './scheduled-task.js';

export type WindowsTunnelLifecycleAction = 'start' | 'stop' | 'uninstall';

export type {
    RunExecutable,
    RunExecutableResult,
};

export interface WindowsTunnelLifecycleDependencies
    extends WindowsScheduledTaskDependencies {}

export interface InstallWindowsTunnelTaskOptions {
    taskName: string;
    task: WindowsTunnelTaskOptions;
    replaceExisting?: boolean;
}

export {
    buildSchtasksLifecycleArgs,
    resolveSchtasksExecutable,
};

export async function installWindowsTunnelTask(
    options: InstallWindowsTunnelTaskOptions,
    dependencies: WindowsTunnelLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    return installWindowsScheduledTask(
        {
            taskName: options.taskName,
            taskXml: buildWindowsTunnelTaskXml(options.task),
            tempPrefix: 'desktop-commander-tunnel-task-',
            replaceExisting: options.replaceExisting,
        },
        dependencies,
    );
}

export async function startWindowsTunnelTask(
    taskName: string,
    dependencies: WindowsTunnelLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    return runWindowsScheduledTaskAction('start', taskName, dependencies);
}

export async function stopWindowsTunnelTask(
    taskName: string,
    dependencies: WindowsTunnelLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    return runWindowsScheduledTaskAction('stop', taskName, dependencies);
}

export async function uninstallWindowsTunnelTask(
    taskName: string,
    dependencies: WindowsTunnelLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    return runWindowsScheduledTaskAction('uninstall', taskName, dependencies);
}
