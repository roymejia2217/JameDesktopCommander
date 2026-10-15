#!/usr/bin/env node
/** Embed read-only Git provenance in the compiled output, never a host path. */
import { execFileSync } from 'node:child_process';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
if (typeof pkg.version !== 'string' || !/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(pkg.version)) {
  throw new Error('Invalid package version for build provenance');
}

function git(args) {
  return execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8', timeout: 5000, maxBuffer: 256 * 1024,
    windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
}

let provenance = { schemaVersion: 1, kind: 'unavailable', packageVersion: pkg.version };
try {
  const gitRoot = resolve(git(['rev-parse', '--show-toplevel']));
  if (gitRoot.toLowerCase() !== root.toLowerCase()) {
    throw new Error('Source tree is not the expected Git root');
  }
  const sourceCommit = git(['rev-parse', 'HEAD']);
  if (!/^[a-f0-9]{40}$/.test(sourceCommit)) throw new Error('Invalid Git revision');
  const workspaceClean = git(['status', '--porcelain', '--untracked-files=normal']) === '';
  provenance = { schemaVersion: 1, kind: 'git', packageVersion: pkg.version,
    sourceCommit, workspaceClean };
} catch {
  // Archive builds without .git cannot claim verified revision provenance.
  // A release gate must reject 'unavailable' rather than guess.
}

const destination = join(root, 'dist', 'build-provenance.json');
await mkdir(dirname(destination), { recursive: true });
await writeFile(destination, JSON.stringify(provenance, null, 2) + '\n', { flag: 'w' });
