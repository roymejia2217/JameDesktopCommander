import {
    buildWindowsUiBridgeTaskXml,
    type WindowsUiBridgeTaskOptions,
} from './ui-bridge-task.js';
import {
    installWindowsScheduledTask,
    runWindowsScheduledTaskAction,
    type RunExecutableResult,
    type WindowsScheduledTaskDependencies,
} from './scheduled-task.js';

export interface WindowsUiBridgeLifecycleDependencies
    extends WindowsScheduledTaskDependencies {}

export interface InstallWindowsUiBridgeTaskOptions {
    taskName: string;
    task: WindowsUiBridgeTaskOptions;
    replaceExisting?: boolean;
}

export async function installWindowsUiBridgeTask(
    options: InstallWindowsUiBridgeTaskOptions,
    dependencies: WindowsUiBridgeLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    return installWindowsScheduledTask(
        {
            taskName: options.taskName,
            taskXml: buildWindowsUiBridgeTaskXml(options.task),
            tempPrefix: 'jame-desktop-commander-ui-bridge-task-',
            replaceExisting: options.replaceExisting ?? false,
        },
        dependencies,
    );
}

export async function startWindowsUiBridgeTask(
    taskName: string,
    dependencies: WindowsUiBridgeLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    return runWindowsScheduledTaskAction('start', taskName, dependencies);
}

export async function stopWindowsUiBridgeTask(
    taskName: string,
    dependencies: WindowsUiBridgeLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    return runWindowsScheduledTaskAction('stop', taskName, dependencies);
}

export async function uninstallWindowsUiBridgeTask(
    taskName: string,
    dependencies: WindowsUiBridgeLifecycleDependencies = {},
): Promise<RunExecutableResult> {
    return runWindowsScheduledTaskAction('uninstall', taskName, dependencies);
}
