'use strict';

// Experimental policy state machine. Not imported by JDC's MCP runtime.
const path = require('node:path');

class CapabilityPolicyDenied extends Error {
  constructor() {
    super('Restricted filesystem capability unavailable or denied');
    this.name = 'CapabilityPolicyDenied';
    this.code = 'E_CAPABILITY_POLICY';
  }
}

function deny() { return new CapabilityPolicyDenied(); }

function validateSnapshot(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      value.mode !== 'restricted' ||
      typeof value.revision !== 'string' || value.revision.length === 0 ||
      !Array.isArray(value.allowedRoots) || value.allowedRoots.length === 0) {
    throw deny();
  }
  const roots = [];
  const seen = new Set();
  for (const root of value.allowedRoots) {
    if (typeof root !== 'string' || !path.isAbsolute(root) || root.includes('\0')) {
      throw deny();
    }
    const absolute = path.resolve(root);
    if (absolute === path.parse(absolute).root) throw deny();
    if (seen.has(absolute)) throw deny();
    seen.add(absolute);
    roots.push(absolute);
  }
  return Object.freeze({
    signature: JSON.stringify([value.revision, roots]),
    roots: Object.freeze(roots),
  });
}

function contains(root, requested) {
  const relative = path.relative(root, requested);
  if (!relative || relative === '..' || relative.startsWith('..' + path.sep) ||
      path.isAbsolute(relative)) return null;
  return relative;
}

class RestrictedCapabilityPolicy {
  #readPolicy;
  #RootCapability;
  #generation = 0;
  #entries = [];
  #signature = null;
  #state = 'uninitialized';
  #permanentlyClosed = false;

  constructor({ readVerifiedPolicy, RootCapability } = {}) {
    if (typeof readVerifiedPolicy !== 'function' ||
        typeof RootCapability !== 'function' ||
        !['readBytes', 'writeBytes', 'close'].every(name =>
          typeof RootCapability.prototype?.[name] === 'function')) {
      throw deny(); // A missing/wrong native ABI must never grant pathname fallback.
    }
    this.#readPolicy = readVerifiedPolicy;
    this.#RootCapability = RootCapability;
  }

  get state() { return this.#state; }

  #revoke(permanent = false) {
    this.#generation++;
    this.#permanentlyClosed ||= permanent;
    const old = this.#entries;
    this.#entries = [];
    this.#signature = null;
    this.#state = this.#permanentlyClosed ? 'closed' : 'revoked';
    const failures = [];
    for (const { capability } of old) {
      try { capability.close(); } catch (error) { failures.push(error); }
    }
    if (failures.length) {
      this.#permanentlyClosed = true;
      this.#state = 'closed';
      throw new AggregateError(failures, 'Native capability close failed; policy permanently denied');
    }
  }

  invalidate() {
    if (!this.#permanentlyClosed) this.#revoke();
  }

  close() {
    if (!this.#permanentlyClosed) this.#revoke(true);
  }

  async reload() {
    if (this.#permanentlyClosed) throw deny();
    this.#revoke(); // Old policy must be unusable BEFORE awaiting a new snapshot.
    const generation = this.#generation;
    let snapshot;
    try { snapshot = validateSnapshot(await this.#readPolicy()); }
    catch { throw deny(); }
    if (generation !== this.#generation || this.#permanentlyClosed) throw deny();
    const created = [];
    try {
      for (const root of snapshot.roots) {
        const capability = new this.#RootCapability(root);
        if (!capability || !['readBytes', 'writeBytes', 'close'].every(name =>
            typeof capability[name] === 'function')) throw deny();
        created.push({ root, capability });
      }
    } catch {
      let failedClose = false;
      for (const { capability } of created) {
        try { capability.close(); } catch { failedClose = true; }
      }
      if (failedClose) this.#revoke(true);
      throw deny();
    }
    this.#entries = created;
    this.#signature = snapshot.signature;
    this.#state = 'active';
  }

  async #resolve(requestedPath) {
    if (this.#state !== 'active' || this.#permanentlyClosed) throw deny();
    const generation = this.#generation;
    let latest;
    try { latest = validateSnapshot(await this.#readPolicy()); }
    catch {
      if (generation === this.#generation) this.#revoke();
      throw deny();
    }
    if (generation !== this.#generation || this.#state !== 'active') throw deny();
    if (latest.signature !== this.#signature) {
      this.#revoke(); // Deny the in-flight call; reload must be explicit.
      throw deny();
    }
    if (typeof requestedPath !== 'string' || !path.isAbsolute(requestedPath) ||
        requestedPath.includes('\0')) throw deny();
    const absolute = path.resolve(requestedPath);
    let best = null;
    for (const entry of this.#entries) {
      const relative = contains(entry.root, absolute);
      if (relative !== null && (!best || entry.root.length > best.root.length)) {
        best = { ...entry, relative };
      }
    }
    if (!best) throw deny();
    return best; // Native path resolution is the actual confinement boundary.
  }

  async readBytes(requestedPath) {
    const { capability, relative } = await this.#resolve(requestedPath);
    const bytes = capability.readBytes(relative);
    if (!Buffer.isBuffer(bytes)) { this.invalidate(); throw deny(); }
    return bytes;
  }

  async writeBytes(requestedPath, bytes, mode) {
    if (!Buffer.isBuffer(bytes) || (mode !== 'rewrite' && mode !== 'append')) throw deny();
    const { capability, relative } = await this.#resolve(requestedPath);
    capability.writeBytes(relative, bytes, mode);
  }
}

module.exports = { RestrictedCapabilityPolicy, CapabilityPolicyDenied };
