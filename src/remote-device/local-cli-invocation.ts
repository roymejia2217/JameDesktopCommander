import path from 'node:path';

export interface LocalRemoteCommand {
    readonly platform: NodeJS.Platform;
    readonly executable: string;
    readonly entrypoint: string;
    readonly option?: '' | '--help' | '--debug' | '--logout';
}

const safeArgument = (value: string, platform: NodeJS.Platform): string => {
    if (typeof value !== 'string' || !value ||
        /[\u0000-\u001f\u007f]/u.test(value) ||
        !(platform === 'win32' ? path.win32 : path.posix).isAbsolute(value)) {
        throw new Error('Invalid local JDC command');
    }
    return platform === 'win32'
        ? "'" + value.replace(/'/g, "''") + "'"
        : "'" + value.replace(/'/g, "'\\''") + "'";
};

/** Copyable command for the *running local JDC*, never a public npm package. */
export function formatLocalRemoteCommand(input: LocalRemoteCommand): string {
    if (!input || !['win32', 'linux', 'darwin'].includes(input.platform) ||
        !['', '--help', '--debug', '--logout'].includes(input.option ?? '')) {
        throw new Error('Invalid local JDC command');
    }
    const executable = safeArgument(input.executable, input.platform);
    const entrypoint = safeArgument(input.entrypoint, input.platform);
    const prefix = input.platform === 'win32' ? '& ' : '';
    const option = input.option ? ' ' + input.option : '';
    return prefix + executable + ' ' + entrypoint + ' remote' + option;
}

/** The same invocation used by the current process, or no suggestion at all. */
export function currentLocalRemoteCommand(option: LocalRemoteCommand['option'] = ''): string | null {
    if (!process.argv[1]) return null;
    try {
        return formatLocalRemoteCommand({
            platform: process.platform,
            executable: process.execPath,
            entrypoint: process.argv[1],
            option,
        });
    } catch {
        return null;
    }
}
