import { execFile } from 'node:child_process';
import { readFile as readTextFile } from 'node:fs/promises';
import path from 'node:path';

import { XMLParser } from 'fast-xml-parser';
import YAML from 'yaml';

import {
    buildSchtasksQueryXmlArgs,
    resolveSchtasksExecutable,
    type RunExecutable,
    type RunExecutableResult,
} from './scheduled-task.js';

const PROFILE_NAME_PATTERN = /^[A-Za-z0-9._-]+$/;
const RUN_ARGUMENTS_PATTERN =
    /^run --profile-dir "([^"]+)" --profile ([A-Za-z0-9._-]+)$/;

export interface WindowsTunnelTaskRegistration {
    executable: string;
    profileDir: string;
    profileName: string;
}

export interface WindowsTunnelRegistration {
    taskName: string;
    task: {
        registered: true;
        executable: string;
        profileDir: string;
        profileName: string;
    };
    profile: {
        path: string;
        healthUrlFile: string;
    };
}

export interface WindowsTunnelStatus extends WindowsTunnelRegistration {
    health: {
        result: string;
        baseUrl: string;
        live: boolean;
        ready: boolean;
        controlPlanePoll: boolean;
    };
}

export interface WindowsTunnelStatusDependencies {
    environment?: Record<string, string | undefined>;
    runExecutable?: RunExecutable;
    readFile?: (filePath: string) => Promise<string>;
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

function requireObject(
    label: string,
    value: unknown,
): Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${label} must be an object.`);
    }
    return value as Record<string, unknown>;
}

function requireString(label: string, value: unknown): string {
    if (typeof value !== 'string' || !value.trim()) {
        throw new Error(`${label} must be a non-empty string.`);
    }
    return value.trim();
}

function requireAbsoluteWindowsPath(label: string, value: unknown): string {
    const normalized = requireString(label, value);
    if (!path.win32.isAbsolute(normalized)) {
        throw new Error(`${label} must be an absolute Windows path.`);
    }
    return path.win32.normalize(normalized);
}

export function parseWindowsTunnelTaskRegistration(
    taskXml: string,
): WindowsTunnelTaskRegistration {
    const parser = new XMLParser({
        ignoreAttributes: true,
        removeNSPrefix: true,
        processEntities: true,
        trimValues: true,
    });
    const document = requireObject('Task XML document', parser.parse(taskXml));
    const task = requireObject('Task XML Task', document.Task);
    const actions = requireObject('Task XML Actions', task.Actions);
    const execAction = actions.Exec;
    if (Array.isArray(execAction)) {
        throw new Error('Tunnel task must contain exactly one Exec action.');
    }
    const execNode = requireObject('Task XML Exec', execAction);
    const executable = requireAbsoluteWindowsPath(
        'Tunnel task executable',
        execNode.Command,
    );
    const argumentsText = requireString(
        'Tunnel task arguments',
        execNode.Arguments,
    );
    const match = RUN_ARGUMENTS_PATTERN.exec(argumentsText);
    if (!match) {
        throw new Error('Tunnel task arguments do not match the supported run contract.');
    }
    const profileDir = requireAbsoluteWindowsPath(
        'Tunnel profile directory',
        match[1],
    );
    const profileName = match[2];
    if (!PROFILE_NAME_PATTERN.test(profileName)) {
        throw new Error('Tunnel profile name is invalid.');
    }
    return { executable, profileDir, profileName };
}

function parseProfileList(
    rawJson: string,
    profileName: string,
): string {
    let parsed: unknown;
    try {
        parsed = JSON.parse(rawJson);
    } catch {
        throw new Error('Tunnel profile list output is not valid JSON.');
    }
    if (!Array.isArray(parsed)) {
        throw new Error('Tunnel profile list output must be an array.');
    }
    const entry = parsed.find((item) => {
        if (typeof item !== 'object' || item === null || Array.isArray(item)) {
            return false;
        }
        return (item as Record<string, unknown>).name === profileName;
    });
    if (!entry) {
        throw new Error(`Tunnel profile "${profileName}" was not found.`);
    }
    return requireAbsoluteWindowsPath(
        'Tunnel profile path',
        (entry as Record<string, unknown>).path,
    );
}

function parseHealthUrlFile(profileText: string): string {
    const profile = requireObject('Tunnel profile', YAML.parse(profileText));
    const health = requireObject('Tunnel profile health', profile.health);
    return requireAbsoluteWindowsPath(
        'Tunnel profile health.url_file',
        health.url_file,
    );
}

function parseHealthOutput(rawJson: string): WindowsTunnelStatus['health'] {
    let parsed: unknown;
    try {
        parsed = JSON.parse(rawJson);
    } catch {
        throw new Error('Tunnel health output is not valid JSON.');
    }
    const root = requireObject('Tunnel health output', parsed);
    const healthz = requireObject('Tunnel health output healthz', root.healthz);
    const readyz = requireObject('Tunnel health output readyz', root.readyz);
    const controlPlanePoll = requireObject(
        'Tunnel health output control_plane_poll',
        root.control_plane_poll,
    );
    if (
        typeof healthz.ok !== 'boolean' ||
        typeof readyz.ok !== 'boolean' ||
        typeof controlPlanePoll.ok !== 'boolean'
    ) {
        throw new Error('Tunnel health output contains invalid readiness fields.');
    }
    return {
        result: requireString('Tunnel health output result', root.result),
        baseUrl: requireString('Tunnel health output base_url', root.base_url),
        live: healthz.ok,
        ready: readyz.ok,
        controlPlanePoll: controlPlanePoll.ok,
    };
}

function resolveDependencies(
    dependencies: WindowsTunnelStatusDependencies,
): Required<WindowsTunnelStatusDependencies> {
    return {
        environment: dependencies.environment ?? process.env,
        runExecutable: dependencies.runExecutable ?? defaultRunExecutable,
        readFile:
            dependencies.readFile ??
            ((filePath) => readTextFile(filePath, { encoding: 'utf8' })),
    };
}
export async function getWindowsTunnelRegistration(
    taskName: string,
    dependencies: WindowsTunnelStatusDependencies = {},
): Promise<WindowsTunnelRegistration> {
    const deps = resolveDependencies(dependencies);
    const schtasksExecutable = resolveSchtasksExecutable(deps.environment);
    const taskQuery = await deps.runExecutable(
        schtasksExecutable,
        buildSchtasksQueryXmlArgs(taskName),
    );
    const registration = parseWindowsTunnelTaskRegistration(taskQuery.stdout);

    const profileList = await deps.runExecutable(registration.executable, [
        'profiles',
        'list',
        '--profile-dir',
        registration.profileDir,
        '--json',
    ]);
    const profilePath = parseProfileList(
        profileList.stdout,
        registration.profileName,
    );
    const profileText = await deps.readFile(profilePath);
    const healthUrlFile = parseHealthUrlFile(profileText);

    return {
        taskName,
        task: {
            registered: true,
            executable: registration.executable,
            profileDir: registration.profileDir,
            profileName: registration.profileName,
        },
        profile: {
            path: profilePath,
            healthUrlFile,
        },
    };
}

export async function getWindowsTunnelStatus(
    taskName: string,
    dependencies: WindowsTunnelStatusDependencies = {},
): Promise<WindowsTunnelStatus> {
    const deps = resolveDependencies(dependencies);
    const registration = await getWindowsTunnelRegistration(
        taskName,
        dependencies,
    );

    const healthProbe = await deps.runExecutable(registration.task.executable, [
        'health',
        '--json',
        '--url-file',
        registration.profile.healthUrlFile,
        '--require-control-plane-poll',
    ]);
    const health = parseHealthOutput(healthProbe.stdout);

    return {
        ...registration,
        health,
    };
}
