import path from 'node:path';

import {
    escapeWindowsTaskXml,
    requireAbsoluteWindowsPath,
    requireNonEmpty,
} from './scheduled-task.js';

export const DEFAULT_WINDOWS_TUNNEL_RESTART_SUPERVISOR_TASK_NAME =
    'JameDesktopCommander Tunnel Restart Supervisor';

export interface WindowsTunnelRestartSupervisorTaskOptions {
    author: string;
    nodeExecutable: string;
    workerScript: string;
    tunnelTaskName: string;
}

export function buildWindowsTunnelRestartSupervisorTaskXml(
    options: WindowsTunnelRestartSupervisorTaskOptions,
): string {
    const author = requireNonEmpty('Task author', options.author);
    const nodeExecutable = requireAbsoluteWindowsPath(
        'Node executable',
        options.nodeExecutable,
    );
    const workerScript = requireAbsoluteWindowsPath(
        'Tunnel restart worker script',
        options.workerScript,
    );
    const tunnelTaskName = requireNonEmpty(
        'Tunnel task name',
        options.tunnelTaskName,
    );
    const workingDirectory = path.win32.dirname(workerScript);
    const argumentsText =
        `"${workerScript}" --task-name "${tunnelTaskName}"`;

    return [
        '<?xml version="1.0" encoding="UTF-16"?>',
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
        '  <RegistrationInfo>',
        `    <Author>${escapeWindowsTaskXml(author)}</Author>`,
        '    <Description>Runs the JameDesktopCommander Secure MCP Tunnel restart supervisor outside the tunnel process tree.</Description>',
        '  </RegistrationInfo>',
        '  <Triggers />',
        '  <Principals>',
        '    <Principal id="Author">',
        `      <UserId>${escapeWindowsTaskXml(author)}</UserId>`,
        '      <LogonType>S4U</LogonType>',
        '      <RunLevel>LeastPrivilege</RunLevel>',
        '    </Principal>',
        '  </Principals>',
        '  <Settings>',
        '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>',
        '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>',
        '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>',
        '    <AllowHardTerminate>true</AllowHardTerminate>',
        '    <StartWhenAvailable>false</StartWhenAvailable>',
        '    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>',
        '    <WakeToRun>false</WakeToRun>',
        '    <Enabled>true</Enabled>',
        '    <Hidden>false</Hidden>',
        '    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>',
        '    <Priority>7</Priority>',
        '  </Settings>',
        '  <Actions Context="Author">',
        '    <Exec>',
        `      <Command>${escapeWindowsTaskXml(nodeExecutable)}</Command>`,
        `      <Arguments>${escapeWindowsTaskXml(argumentsText)}</Arguments>`,
        `      <WorkingDirectory>${escapeWindowsTaskXml(workingDirectory)}</WorkingDirectory>`,
        '    </Exec>',
        '  </Actions>',
        '</Task>',
        '',
    ].join('\r\n');
}
