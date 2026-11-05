/**
 * Observational classification of the official tunnel-client profile schema.
 * Not a file existence/ownership test and NEVER permission to rotate a key.
 * Source values, keys, paths and parse errors must not enter the result.
 */
export type TunnelCredentialSource =
    | 'file_reference' | 'environment_reference' | 'unsupported' | 'unverified';

function record(value: unknown): Record<string, unknown> | null {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? value as Record<string, unknown> : null;
}

export function classifyTunnelCredentialSource(profile: unknown): TunnelCredentialSource {
    const controlPlane = record(record(profile)?.control_plane);
    if (!controlPlane || controlPlane.api_key == null) return 'unverified';
    const reference = controlPlane.api_key;
    if (typeof reference !== 'string') return 'unsupported';
    if (/^env:[A-Za-z_][A-Za-z0-9_]*$/.test(reference)) {
        return 'environment_reference';
    }
    if (reference.startsWith('file:')) {
        const target = reference.slice('file:'.length);
        if (/[\u0000-\u001f\u007f]/.test(target) ||
            target.split(/[\\/]/).includes('..')) {
            return 'unsupported';
        }
        const posix = target.startsWith('/') &&
            !target.startsWith('//') && target.length > 1 && !target.includes('\\');
        const windows = /^[A-Za-z]:[\\/][^\\/]/.test(target);
        if (posix || windows) return 'file_reference';
    }
    return 'unsupported';
}
