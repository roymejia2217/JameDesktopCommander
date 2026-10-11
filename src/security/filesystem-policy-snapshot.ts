import { createHash } from 'node:crypto';
import path from 'node:path';

/** Disk-observed candidate, NOT an atomic filesystem authorization capability. */
export interface FilesystemPolicyCandidateSnapshot {
  readonly mode: 'restricted' | 'unrestricted' | 'legacy-unset';
  readonly revision: string;
  readonly allowedRoots: readonly string[];
}

function invalid(): Error {
  return new Error('Invalid persisted filesystem policy candidate');
}

/**
 * Deterministic projection of one persisted config-file read. A digest of
 * current content is not a monotonic revision: ABA and concurrent mutations
 * remain release-blocking until an authoritative versioned policy exists.
 */
export function parseFilesystemPolicyCandidate(config: unknown): FilesystemPolicyCandidateSnapshot {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    throw invalid();
  }
  const persisted = config as Record<string, unknown>;
  const present = Object.prototype.hasOwnProperty.call(persisted, 'allowedDirectories');
  const value = persisted.allowedDirectories;
  if (present && (!Array.isArray(value) ||
      value.some((root: unknown) => typeof root !== 'string' || root.trim().length === 0))) {
    throw invalid();
  }

  let mode: FilesystemPolicyCandidateSnapshot['mode'];
  let roots: string[];
  if (!present) {
    mode = 'legacy-unset';
    roots = [];
  } else if ((value as string[]).length === 0 || (value as string[]).includes('/')) {
    // An explicit empty list and '/' mean unrestricted access in legacy JDC.
    mode = 'unrestricted';
    roots = [];
  } else {
    mode = 'restricted';
    roots = [...value as string[]];
    const seen = new Set<string>();
    for (const root of roots) {
      // Never silently widen a relative/home/unnormalized/volume-root path.
      if (root.includes('\0') || !path.isAbsolute(root) || path.resolve(root) !== root ||
          path.parse(root).root === root || seen.has(root)) {
        throw invalid();
      }
      seen.add(root);
    }
  }
  const revision = createHash('sha256').update(JSON.stringify([mode, roots])).digest('hex');
  return Object.freeze({ mode, revision, allowedRoots: Object.freeze(roots) });
}
