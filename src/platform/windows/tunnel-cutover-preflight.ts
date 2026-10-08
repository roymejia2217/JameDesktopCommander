import { createHash } from 'node:crypto';
import path from 'node:path';
import YAML from 'yaml';

export interface WindowsTunnelRuntimeProfileCutoverOptions {
    originalEntry: string;
    candidateEntry: string;
    allowedRoot: string;
}

export interface WindowsTunnelRuntimeProfileCutoverPlan {
    originalSha256: string;
    stagedSha256: string;
    stagedProfile: string;
    profileChanges: 1;
}

function requiredRuntimeEntry(entry: string, root: string): void {
    if (!path.win32.isAbsolute(entry) || !path.win32.isAbsolute(root)) {
        throw new Error('Tunnel runtime path and trusted root must be absolute.');
    }
    if (/[\r\n"'\0]/.test(entry + root)) {
        throw new Error('Tunnel runtime path contains invalid characters.');
    }
    const normalizedEntry = path.win32.normalize(entry);
    const normalizedRoot = path.win32.normalize(root);
    const suffix = path.win32.relative(normalizedRoot, normalizedEntry);
    if (
        suffix === '' || suffix === '..' ||
        suffix.startsWith('..' + path.win32.sep) ||
        path.win32.isAbsolute(suffix)
    ) {
        throw new Error('Tunnel runtime entry is outside the allowed root.');
    }
    if (
        !/\\JameDesktopCommander-runtime-[a-f0-9]{6,40}\\dist\\index\.js$/i.test(normalizedEntry)
    ) {
        throw new Error('Tunnel runtime entry does not match a pinned worktree.');
    }
}

function parsedProfile(text: string): Record<string, unknown> {
    const document = YAML.parseDocument(text, { uniqueKeys: true, strict: true });
    if (document.errors.length > 0) {
        throw new Error('Tunnel profile contains invalid or ambiguous YAML.');
    }
    const profile = document.toJS();
    if (!profile || Array.isArray(profile) || typeof profile !== 'object') {
        throw new Error('Tunnel profile must be an object.');
    }
    return profile as Record<string, unknown>;
}

function onlyCommand(profile: Record<string, unknown>): string {
    const mcp = profile.mcp as Record<string, unknown> | undefined;
    const commands = mcp?.commands;
    if (!Array.isArray(commands) || commands.length !== 1) {
        throw new Error('Tunnel profile must have exactly one MCP command.');
    }
    const command = commands[0];
    if (
        !command || typeof command !== 'object' ||
        typeof command.command !== 'string'
    ) {
        throw new Error('Tunnel profile MCP command is invalid.');
    }
    return command.command;
}

function countOccurrences(text: string, term: string): number {
    return text.split(term).length - 1;
}

function fingerprint(text: string): string {
    return createHash('sha256').update(text, 'utf8').digest('hex').toUpperCase();
}

/**
 * Read-only, fail-closed cutover planning. stagedProfile may contain
 * credentials from the input: callers must NEVER log or display it.
 * This function performs no filesystem or process mutation.
 */
export function planWindowsTunnelRuntimeProfileCutover(
    profileText: string,
    options: WindowsTunnelRuntimeProfileCutoverOptions,
): WindowsTunnelRuntimeProfileCutoverPlan {
    requiredRuntimeEntry(options.originalEntry, options.allowedRoot);
    requiredRuntimeEntry(options.candidateEntry, options.allowedRoot);
    if (
        path.win32.normalize(options.originalEntry).toLowerCase() ===
        path.win32.normalize(options.candidateEntry).toLowerCase()
    ) {
        throw new Error('Original and candidate tunnel runtimes are identical.');
    }

    const before = parsedProfile(profileText);
    const beforeCommand = onlyCommand(before);
    const variants = [
        options.originalEntry,
        options.originalEntry.split('\\').join('\\\\'),
    ];
    const active = variants.filter((value) => countOccurrences(profileText, value) > 0);
    if (active.length !== 1 || countOccurrences(profileText, active[0]) !== 1) {
        throw new Error('Expected exactly one unambiguous runtime reference.');
    }
    const replacement = active[0] === variants[0]
        ? options.candidateEntry
        : options.candidateEntry.split('\\').join('\\\\');
    const stagedProfile = profileText.replace(active[0], replacement);
    const after = parsedProfile(stagedProfile);
    const afterCommand = onlyCommand(after);

    if (
        countOccurrences(beforeCommand, options.originalEntry) !== 1 ||
        afterCommand !== beforeCommand.replace(
            options.originalEntry,
            options.candidateEntry,
        )
    ) {
        throw new Error('Runtime reference must change only the MCP command.');
    }
    const expected = structuredClone(before) as Record<string, unknown>;
    const mcp = expected.mcp as { commands: Array<{ command: string }> };
    mcp.commands[0].command = afterCommand;
    // Assertion libraries may embed sensitive profile values in thrown errors.
    if (JSON.stringify(after) !== JSON.stringify(expected)) {
        throw new Error('Unrelated tunnel profile fields changed.');
    }
    if (beforeCommand === afterCommand) {
        throw new Error('Tunnel runtime command was unchanged.');
    }

    return {
        originalSha256: fingerprint(profileText),
        stagedSha256: fingerprint(stagedProfile),
        stagedProfile,
        profileChanges: 1,
    };
}
