import { createHash } from 'node:crypto';

export const POLICY_GENERATION_KEY = '__jdcFilesystemPolicyGeneration';
export const POLICY_FINGERPRINT_KEY = '__jdcFilesystemPolicyFingerprint';

type PersistedObject = Record<string, unknown>;

function has(object: PersistedObject, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function unavailable(): Error {
  return new Error('Filesystem policy generation unavailable');
}

export function persistedPolicyFingerprint(config: PersistedObject): string {
  // Preserve the difference between an absent key and an explicit [].
  const present = has(config, 'allowedDirectories');
  return createHash('sha256')
    .update(JSON.stringify([present, present ? config.allowedDirectories : null]))
    .digest('hex');
}

export function readCooperativePolicyGeneration(config: PersistedObject): number | null {
  const hasGeneration = has(config, POLICY_GENERATION_KEY);
  const hasFingerprint = has(config, POLICY_FINGERPRINT_KEY);
  if (!hasGeneration && !hasFingerprint) return null; // Legacy/unmanaged state.
  if (!hasGeneration || !hasFingerprint) throw unavailable();
  const generation = config[POLICY_GENERATION_KEY];
  const fingerprint = config[POLICY_FINGERPRINT_KEY];
  if (typeof generation !== 'number' || !Number.isSafeInteger(generation) ||
      generation < 1 || typeof fingerprint !== 'string' ||
      !/^[0-9a-f]{64}$/.test(fingerprint) ||
      fingerprint !== persistedPolicyFingerprint(config)) {
    throw unavailable();
  }
  return generation;
}

/**
 * Executed inside ConfigManager's existing cross-process config mutation lock,
 * before its atomic rename. Preserves a cooperative generation across *all*
 * regular JDC writers; does not establish trust against an arbitrary editor
 * capable of replacing the whole config, rollback/ABA, or process crashes.
 */
export function stampCooperativePolicyMutation(
  before: PersistedObject,
  after: PersistedObject,
): void {
  const old = persistedPolicyFingerprint(before);
  const next = persistedPolicyFingerprint(after);
  const changed = old !== next;
  const previousGeneration = readCooperativePolicyGeneration(before);
  const forgedMetadata = has(after, POLICY_GENERATION_KEY) &&
    after[POLICY_GENERATION_KEY] !== before[POLICY_GENERATION_KEY];
  const forgedFingerprint = has(after, POLICY_FINGERPRINT_KEY) &&
    after[POLICY_FINGERPRINT_KEY] !== before[POLICY_FINGERPRINT_KEY];
  if (forgedMetadata || forgedFingerprint) {
    throw unavailable(); // Configuration API callers may not forge the markers.
  }
  if (changed) {
    if (previousGeneration === Number.MAX_SAFE_INTEGER) throw unavailable();
    after[POLICY_GENERATION_KEY] = (previousGeneration ?? 0) + 1;
    after[POLICY_FINGERPRINT_KEY] = next;
  } else if (previousGeneration !== null) {
    // resetConfig() clears the object; unrelated changes must retain metadata.
    after[POLICY_GENERATION_KEY] = previousGeneration;
    after[POLICY_FINGERPRINT_KEY] = old;
  }
}
