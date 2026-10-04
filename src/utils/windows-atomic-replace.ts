import fs from 'node:fs/promises';

type Win32Function = (...args: unknown[]) => number;

type Win32FileApi = Readonly<{
    replaceFile: Win32Function;
    getLastError: () => number;
}>;

const ERROR_FILE_NOT_FOUND = 2;
const ERROR_PATH_NOT_FOUND = 3;
const ERROR_ACCESS_DENIED = 5;
const ERROR_SHARING_VIOLATION = 32;

let apiPromise: Promise<Win32FileApi> | undefined;

function makeWin32Error(code: number, target: string, cause?: unknown): NodeJS.ErrnoException {
    const mappedCode =
        code === ERROR_FILE_NOT_FOUND || code === ERROR_PATH_NOT_FOUND
            ? 'ENOENT'
            : code === ERROR_ACCESS_DENIED
              ? 'EACCES'
              : code === ERROR_SHARING_VIOLATION
                ? 'EBUSY'
                : 'EIO';

    const error = new Error(
        `ReplaceFileW failed for ${target} with Win32 error ${code}`,
    ) as NodeJS.ErrnoException & { win32Code?: number; cause?: unknown };
    error.code = mappedCode;
    error.win32Code = code;
    if (cause !== undefined) error.cause = cause;
    return error;
}

async function loadWin32FileApi(): Promise<Win32FileApi> {
    if (process.platform !== 'win32') {
        throw new Error('Win32 file replacement is only available on Windows');
    }
    if (apiPromise) return apiPromise;

    apiPromise = (async () => {
        const { default: koffi } = await import('koffi');
        const kernel32 = koffi.load('kernel32.dll');
        const replaceFile = kernel32.func(
            '__stdcall',
            'ReplaceFileW',
            'int',
            ['str16', 'str16', 'str16', 'uint32_t', 'void *', 'void *'],
        ) as unknown as Win32Function;
        const getLastError = kernel32.func(
            '__stdcall',
            'GetLastError',
            'uint32_t',
            [],
        ) as unknown as () => number;
        return Object.freeze({ replaceFile, getLastError });
    })();

    try {
        return await apiPromise;
    } catch (error) {
        apiPromise = undefined;
        throw error;
    }
}

export async function replaceFileWin32(target: string, replacement: string): Promise<void> {
    const api = await loadWin32FileApi();
    const replaced = api.replaceFile(target, replacement, null, 0, null, null);
    if (replaced !== 0) return;

    const win32Code = api.getLastError();

    if (win32Code === ERROR_FILE_NOT_FOUND || win32Code === ERROR_PATH_NOT_FOUND) {
        await fs.rename(replacement, target);
        return;
    }

    if (win32Code === ERROR_ACCESS_DENIED || win32Code === ERROR_SHARING_VIOLATION) {
        try {
            await fs.rename(replacement, target);
            return;
        } catch (renameError) {
            throw makeWin32Error(win32Code, target, renameError);
        }
    }

    throw makeWin32Error(win32Code, target);
}
