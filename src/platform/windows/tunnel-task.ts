import path from 'node:path';

export interface WindowsTunnelTaskOptions {
    author: string;
    executable: string;
    profileDir: string;
    profileName: string;
}

const PROFILE_NAME_PATTERN = /^[A-Za-z0-9._-]+$/;

function escapeXml(value: string): string {
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

function requireNonEmpty(label: string, value: string): string {
    const normalized = value.trim();
    if (!normalized) {
        throw new Error(`${label} must not be empty.`);
    }
    return normalized;
}

function requireAbsoluteWindowsPath(label: string, value: string): string {
    const normalized = requireNonEmpty(label, value);
    if (!path.win32.isAbsolute(normalized)) {
        throw new Error(`${label} must be an absolute Windows path.`);
    }
    return path.win32.normalize(normalized);
}

export function buildWindowsTunnelTaskXml(options: WindowsTunnelTaskOptions): string {
    const author = requireNonEmpty('Task author', options.author);
    const executable = requireAbsoluteWindowsPath('Tunnel executable', options.executable);
    const profileDir = requireAbsoluteWindowsPath('Tunnel profile directory', options.profileDir);
    const profileName = requireNonEmpty('Tunnel profile name', options.profileName);

    if (!PROFILE_NAME_PATTERN.test(profileName)) {
        throw new Error('Tunnel profile name may contain only letters, digits, dot, underscore, and hyphen.');
    }

    const workingDirectory = path.win32.dirname(executable);
    const argumentsText = `run --profile-dir "${profileDir}" --profile ${profileName}`;

    return [
        '<?xml version="1.0" encoding="UTF-16"?>',
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
        '  <RegistrationInfo>',
        `    <Author>${escapeXml(author)}</Author>`,
        '    <Description>Runs the OpenAI Secure MCP Tunnel for Desktop Commander under the owning Windows user context.</Description>',
        '  </RegistrationInfo>',
        '  <Triggers>',
        '    <BootTrigger>',
        '      <Enabled>true</Enabled>',
        '    </BootTrigger>',
        '  </Triggers>',
        '  <Principals>',
        '    <Principal id="Author">',
        `      <UserId>${escapeXml(author)}</UserId>`,
        '      <LogonType>S4U</LogonType>',
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
        `      <Command>${escapeXml(executable)}</Command>`,
        `      <Arguments>${escapeXml(argumentsText)}</Arguments>`,
        `      <WorkingDirectory>${escapeXml(workingDirectory)}</WorkingDirectory>`,
        '    </Exec>',
        '  </Actions>',
        '</Task>',
        '',
    ].join('\r\n');
}

export function buildSchtasksCreateArgs(taskName: string, xmlPath: string): string[] {
    const normalizedTaskName = requireNonEmpty('Task name', taskName);
    const normalizedXmlPath = requireAbsoluteWindowsPath('Task XML path', xmlPath);

    return [
        '/Create',
        '/TN',
        normalizedTaskName,
        '/XML',
        normalizedXmlPath,
        '/F',
    ];
}
