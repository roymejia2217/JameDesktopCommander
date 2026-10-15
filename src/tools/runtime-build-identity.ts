import { readFile } from 'node:fs/promises';

export type RuntimeBuildIdentity =
  | { schemaVersion: 1; kind: 'git'; packageVersion: string;
      sourceCommit: string; workspaceClean: boolean }
  | { schemaVersion: 1; kind: 'unavailable'; packageVersion?: string };

const COMMIT = /^[a-f0-9]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/;

/** Accept a strict allowlist. Never expose untrusted fields or local paths. */
export function parseRuntimeBuildIdentity(raw: unknown): RuntimeBuildIdentity {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Invalid runtime build identity');
  }
  const info = raw as Record<string, unknown>;
  const keys = Object.keys(info);
  const checkKeys = (required: string[]) =>
    keys.length === required.length && keys.every(key => required.includes(key));
  if (info.schemaVersion !== 1 || typeof info.packageVersion !== 'string' ||
      !VERSION.test(info.packageVersion)) {
    throw new Error('Invalid build provenance schema');
  }
  if (info.kind === 'unavailable' &&
      checkKeys(['schemaVersion', 'kind', 'packageVersion'])) {
    return { schemaVersion: 1, kind: 'unavailable', packageVersion: info.packageVersion };
  }
  if (info.kind === 'git' &&
      checkKeys(['schemaVersion', 'kind', 'packageVersion', 'sourceCommit', 'workspaceClean']) &&
      typeof info.sourceCommit === 'string' && COMMIT.test(info.sourceCommit) &&
      typeof info.workspaceClean === 'boolean') {
    return { schemaVersion: 1, kind: 'git',
      packageVersion: info.packageVersion,
      sourceCommit: info.sourceCommit, workspaceClean: info.workspaceClean };
  }
  throw new Error('Invalid or unsupported runtime build identity');
}

/** Missing or invalid packaged provenance must never be reported as verified. */
export async function getRuntimeBuildIdentity(
  read: (file: URL) => Promise<string> =
    async file => readFile(file, 'utf8'),
): Promise<RuntimeBuildIdentity> {
  try {
    const raw = await read(new URL('../build-provenance.json', import.meta.url));
    return parseRuntimeBuildIdentity(JSON.parse(raw));
  } catch {
    return { schemaVersion: 1, kind: 'unavailable' };
  }
}
