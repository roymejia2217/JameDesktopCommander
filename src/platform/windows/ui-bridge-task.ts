import path from 'node:path';

import {
    escapeWindowsTaskXml,
    requireAbsoluteWindowsPath,
    requireNonEmpty,
} from './scheduled-task.js';

export interface WindowsUiBridgeTaskOptions {
    author: string;
    executable: string;
}

export function buildWindowsUiBridgeTaskXml(options: WindowsUiBridgeTaskOptions): string {
    const author = requireNonEmpty('Task author', options.author);
    const executable = requireAbsoluteWindowsPath('UI bridge executable', options.executable);
    const workingDirectory = path.win32.dirname(executable);

    return [
        '<?xml version="1.0" encoding="UTF-16"?>',
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
        '  <RegistrationInfo>',
        `    <Author>${escapeWindowsTaskXml(author)}</Author>`,
        '    <Description>Runs the JameDesktopCommander Windows UI bridge in the owning interactive user session.</Description>',
        '  </RegistrationInfo>',
        '  <Triggers>',
        '    <LogonTrigger>',
        '      <Enabled>true</Enabled>',
        `      <UserId>${escapeWindowsTaskXml(author)}</UserId>`,
        '    </LogonTrigger>',
        '  </Triggers>',
        '  <Principals>',
        '    <Principal id="Author">',
        `      <UserId>${escapeWindowsTaskXml(author)}</UserId>`,
        '      <LogonType>InteractiveToken</LogonType>',
        '      <RunLevel>LeastPrivilege</RunLevel>',
        '    </Principal>',
        '  </Principals>',
        '  <Settings>',
        '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>',
        '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>',
        '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>',
        '    <AllowHardTerminate>true</AllowHardTerminate>',
        '    <StartWhenAvailable>true</StartWhenAvailable>',
        '    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>',
        '    <WakeToRun>false</WakeToRun>',
        '    <Enabled>true</Enabled>',
        '    <Hidden>false</Hidden>',
        '    <IdleSettings>',
        '      <StopOnIdleEnd>false</StopOnIdleEnd>',
        '      <RestartOnIdle>false</RestartOnIdle>',
        '    </IdleSettings>',
        '    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>',
        '    <Priority>7</Priority>',
        '    <RestartOnFailure>',
        '      <Interval>PT1M</Interval>',
        '      <Count>5</Count>',
        '    </RestartOnFailure>',
        '  </Settings>',
        '  <Actions Context="Author">',
        '    <Exec>',
        `      <Command>${escapeWindowsTaskXml(executable)}</Command>`,
        `      <WorkingDirectory>${escapeWindowsTaskXml(workingDirectory)}</WorkingDirectory>`,
        '    </Exec>',
        '  </Actions>',
        '</Task>',
        '',
    ].join('\r\n');
}
