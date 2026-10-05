import {
    installWindowsScheduledTask,
    runWindowsScheduledTaskAction,
    type RunExecutableResult,
    type WindowsScheduledTaskDependencies,
} from './scheduled-task.js';
import {
    buildWindowsTunnelRestartSupervisorTaskXml,
    type WindowsTunnelRestartSupervisorTaskOptions,
} from './tunnel-restart-supervisor-task.js';

export interface InstallWindowsTunnelRestartSupervisorTaskOptions {
    taskName: string;
    task: WindowsTunnelRestartSupervisorTaskOptions;
    replaceExisting?: boolean;
}

export async function installWindowsTunnelRestartSupervisorTask(
    options: InstallWindowsTunnelRestartSupervisorTaskOptions,
    dependencies: WindowsScheduledTaskDependencies = {},
): Promise<RunExecutableResult> {
    return installWindowsScheduledTask(
        {
            taskName: options.taskName,
            taskXml: buildWindowsTunnelRestartSupervisorTaskXml(options.task),
            tempPrefix: 'jame-desktop-commander-tunnel-restart-task-',
            replaceExisting: options.replaceExisting,
        },
        dependencies,
    );
}

export async function startWindowsTunnelRestartSupervisorTask(
    taskName: string,
    dependencies: WindowsScheduledTaskDependencies = {},
): Promise<RunExecutableResult> {
    return runWindowsScheduledTaskAction('start', taskName, dependencies);
}

export async function uninstallWindowsTunnelRestartSupervisorTask(
    taskName: string,
    dependencies: WindowsScheduledTaskDependencies = {},
): Promise<RunExecutableResult> {
    return runWindowsScheduledTaskAction('uninstall', taskName, dependencies);
}
