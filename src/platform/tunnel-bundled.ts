/** Explicit opt-in to the official CLI already included in a JDC installer. */
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function expandBundledTunnelArguments(
    args: readonly string[],
    platform: NodeJS.Platform,
    installationRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..'),
): string[] {
    if (!args.includes('--bundled')) {
        return [...args];
    }
    if (platform !== 'win32' && platform !== 'linux') {
        throw new Error('Unsupported platform for bundled tunnel client.');
    }
    if (args[0] !== 'install' && !(platform === 'linux' && args[0] === 'doctor')) {
        throw new Error('--bundled supports explicit install, or read-only Linux doctor.');
    }
    if (args.filter((value) => value === '--bundled').length !== 1 ||
        args.includes('--tunnel-client-bin')) {
        throw new Error('--bundled conflicts with duplicate or explicit tunnel client selection.');
    }
    const root = platform === 'win32' ? path.win32 : path.posix;
    const executable = platform === 'win32' ? 'tunnel-client.exe' : 'tunnel-client';
    const bundled = root.join(installationRoot, 'tools', 'tunnel-client', executable);
    return [...args.filter((value) => value !== '--bundled'), '--tunnel-client-bin', bundled];
}
