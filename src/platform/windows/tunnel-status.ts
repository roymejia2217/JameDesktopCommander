import { execFile } from 'node:child_process';
import path from 'node:path';

import { XMLParser } from 'fast-xml-parser';
import YAML from 'yaml';
import {
    classifyTunnelCredentialSource,
    type TunnelCredentialSource,
} from '../tunnel-credential-source.js';

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

/** Task Scheduler configuration is untrusted observation, never a launch grant. */
export interface UntrustedWindowsTunnelTaskObservation {
    kind: 'untrusted_task_registration_v1';
    registration: WindowsTunnelTaskRegistration;
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
        /** Syntax only: not proof of file custody or rotation authorization. */
        credentialSource: TunnelCredentialSource;
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

/**
 * Strict readiness contract for CLI health checks and restart acceptance.
 * An active process alone does not establish an authenticated control plane.
 */
export function isWindowsTunnelHealthReady(
    health: WindowsTunnelStatus['health'],
): boolean {
    return health.result === 'ok' &&
        health.live === true &&
        health.ready === true &&
        health.controlPlanePoll === true;
}

export interface WindowsTunnelStatusDependencies {
    environment?: Record<string, string | undefined>;
    runExecutable?: RunExecutable;
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
    // Task Scheduler permits heterogeneous actions. A single Exec element is
    // insufficient when ComHandler/other actions can also run. Reject the
    // complete registration before invoking any task-selected executable.
    const execAction = actions.Exec;
    if (Object.keys(actions).length !== 1 ||
        !Object.prototype.hasOwnProperty.call(actions, 'Exec') ||
        Array.isArray(execAction)) {
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

export function parseWindowsTunnelProfileList(
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

export function parseWindowsTunnelProfileObservation(profileText: string): {
    healthUrlFile: string;
    credentialSource: TunnelCredentialSource;
} {
    let parsed: unknown;
    try {
        parsed = YAML.parse(profileText);
    } catch {
        // YAML parser diagnostics may include raw credential values.
        throw new Error('Invalid tunnel status profile.');
    }
    const profile = requireObject('Tunnel profile', parsed);
    const health = requireObject('Tunnel profile health', profile.health);
    return {
        healthUrlFile: requireAbsoluteWindowsPath(
            'Tunnel profile health.url_file',
            health.url_file,
        ),
        credentialSource: classifyTunnelCredentialSource(profile),
    };
}

export function parseWindowsTunnelTaskEnabled(taskXml: string): boolean {
    const parser = new XMLParser({
        ignoreAttributes: true, removeNSPrefix: true,
        processEntities: true, trimValues: true,
    });
    const document = requireObject('Task XML document', parser.parse(taskXml));
    const task = requireObject('Task XML Task', document.Task);
    const settings = requireObject('Task XML Settings', task.Settings);
    // The Microsoft Task Scheduler settingsType schema defines Enabled as
    // optional with default=true. Windows omits that default in real exports;
    // an operator-disabled task is serialized with explicit Enabled=false.
    if (!Object.prototype.hasOwnProperty.call(settings, 'Enabled')) {
        return true;
    }
    if (settings.Enabled !== true && settings.Enabled !== 'true' &&
        settings.Enabled !== false && settings.Enabled !== 'false') {
        throw new Error('Task Scheduler enabled state must be explicit.');
    }
    return settings.Enabled === true || settings.Enabled === 'true';
}

export async function getWindowsTunnelTaskEnabled(
    taskName: string,
    dependencies: WindowsTunnelStatusDependencies = {},
): Promise<boolean> {
    const deps = resolveDependencies(dependencies);
    const task = await deps.runExecutable(
        resolveSchtasksExecutable(deps.environment),
        buildSchtasksQueryXmlArgs(taskName),
    );
    return parseWindowsTunnelTaskEnabled(task.stdout);
}

export function parseWindowsTunnelHealthOutput(rawJson: string): WindowsTunnelStatus['health'] {
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
    };
}
export async function observeWindowsTunnelTaskRegistration(
    taskName: string,
    dependencies: WindowsTunnelStatusDependencies = {},
): Promise<UntrustedWindowsTunnelTaskObservation> {
    const deps = resolveDependencies(dependencies);
    const taskQuery = await deps.runExecutable(
        resolveSchtasksExecutable(deps.environment),
        buildSchtasksQueryXmlArgs(taskName),
    );
    return {
        kind: 'untrusted_task_registration_v1',
        registration: parseWindowsTunnelTaskRegistration(taskQuery.stdout),
    };
}

/**
 * A task XML Exec path is not installed-client provenance.
 * No caller-supplied runExecutable, user path or matching SID authorizes it.
 * This must remain fail-closed until an independently authenticated native
 * launcher is integrated at the actual process-creation boundary.
 */
export async function getWindowsTunnelRegistration(
    taskName: string,
    dependencies: WindowsTunnelStatusDependencies = {},
): Promise<WindowsTunnelRegistration> {
    await observeWindowsTunnelTaskRegistration(taskName, dependencies);
    throw new Error('Tunnel client executable is not independently verified.');
}

export async function getWindowsTunnelStatus(
    taskName: string,
    dependencies: WindowsTunnelStatusDependencies = {},
): Promise<WindowsTunnelStatus> {
    // Explicit denied status: never run the client observed in task XML.
    await observeWindowsTunnelTaskRegistration(taskName, dependencies);
    throw new Error('Tunnel client executable is not independently verified.');
}
