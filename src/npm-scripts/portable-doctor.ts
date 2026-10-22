import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readFile, readdir } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseRuntimeBuildIdentity } from '../tools/runtime-build-identity.js';

const hex40 = /^[0-9a-f]{40}$/;
const hex64 = /^[0-9a-f]{64}$/;
const targets = new Set(['linux-x64', 'win32-x64']);

function safePath(p: unknown): p is string {
  return typeof p === 'string' && p.length > 0 && !p.includes('\\') &&
    !p.startsWith('/') && p.split('/').every(part => part && part !== '.' && part !== '..');
}
function permitted(p: string, target: string, nativePath: string | undefined): boolean {
  if (!p.includes('/')) return ['LICENSE', 'NODE-LICENSE', 'package.json', 'package-lock.json'].includes(p);
  if (p.startsWith('runtime/')) return p === (target === 'linux-x64' ? 'runtime/node' : 'runtime/node.exe');
  // Packaging authority is established by the independent build-time gate.
  // This user-facing diagnostic only checks declared file consistency; it
  // never identifies or imports an experimental native authority module.
  if (p.startsWith('native/')) return p === nativePath;
  return p.startsWith('dist/') || p.startsWith('node_modules/');
}
async function digest(file: string): Promise<{ sha256: string; byteLength: number }> {
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(file)) {
    const bytes = chunk as Buffer;
    hash.update(bytes);
    size += bytes.byteLength;
  }
  return { sha256: hash.digest('hex'), byteLength: size };
}

type RecordEntry = { path: string; byteLength: number; sha256: string };
type Manifest = { schemaVersion: number; releaseEligible: boolean; kind: string; target: string;
  sourceCommit: string; nodeVersion: string; fileCount: number; files: RecordEntry[];
  entrypoint: string; runtimeExecutable: string; nativeCapabilityAddon?: string };

/** Internal consistency check; never a signature or publisher authentication. */
export async function inspectPortableCandidate(
  root: string,
  target = `${process.platform}-${process.arch}`,
): Promise<{ result: 'PASS'; target: string; fileCount: number; releaseEligible: false }> {
  if (!targets.has(target)) throw new Error('Unsupported portable candidate platform');
  const manifestPath = join(root, 'candidate-manifest.json');
  if (!(await lstat(manifestPath)).isFile()) throw new Error('Invalid portable manifest');
  const m = JSON.parse(await readFile(manifestPath, 'utf8')) as Manifest;
  const nodePath = target === 'linux-x64' ? 'runtime/node' : 'runtime/node.exe';
  if (m.schemaVersion !== 1 || m.releaseEligible !== false ||
      m.kind !== 'unpublished-portable-node-candidate' || m.target !== target ||
      !hex40.test(m.sourceCommit) || m.nodeVersion !== process.version ||
      m.entrypoint !== 'dist/index.js' || m.runtimeExecutable !== nodePath ||
      !Array.isArray(m.files) || m.fileCount !== m.files.length || m.fileCount < 100 ||
      (m.nativeCapabilityAddon !== undefined &&
        (!safePath(m.nativeCapabilityAddon) ||
         m.nativeCapabilityAddon.split('/').length !== 2 ||
         !m.nativeCapabilityAddon.startsWith('native/') ||
         !m.nativeCapabilityAddon.endsWith('.node') ||
         m.nativeCapabilityAddon.length <= 'native/.node'.length))) {
    throw new Error('Invalid portable candidate contract');
  }
  const expected = new Map<string, RecordEntry>();
  for (const item of m.files) {
    if (!item || !safePath(item.path) ||
        !permitted(item.path, target, m.nativeCapabilityAddon) ||
        !Number.isSafeInteger(item.byteLength) || item.byteLength < 0 ||
        !hex64.test(item.sha256) || expected.has(item.path.toLowerCase())) {
      throw new Error('Invalid portable inventory record');
    }
    expected.set(item.path.toLowerCase(), item);
  }
  const seen = new Set<string>();
  async function scan(dir: string): Promise<void> {
    for (const child of await readdir(dir, { withFileTypes: true })) {
      const absolute = join(dir, child.name);
      if (child.isDirectory()) {
        if (dir === root &&
            !(['runtime', 'dist', 'node_modules'].includes(child.name) ||
              (m.nativeCapabilityAddon !== undefined && child.name === 'native'))) {
          throw new Error('Unapproved portable root directory');
        }
        await scan(absolute);
      } else {
        if (!child.isFile()) throw new Error('Nonregular portable payload entry');
        const name = relative(root, absolute).split(sep).join('/');
        if (name === 'candidate-manifest.json') continue;
        const folded = name.toLowerCase();
        const required = expected.get(folded);
        if (!safePath(name) || required?.path !== name || seen.has(folded)) {
          throw new Error('Unapproved portable payload entry');
        }
        seen.add(folded);
        const actual = await digest(absolute);
        if (actual.byteLength !== required.byteLength || actual.sha256 !== required.sha256) {
          throw new Error('Portable payload integrity mismatch');
        }
      }
    }
  }
  await scan(root);
  // Match the build-time contract, including licenses and the locked runtime
  // payload. The inventory map is case-folded, so compare canonical casing too.
  const requiredFiles = [
    nodePath, 'LICENSE', 'NODE-LICENSE', 'package.json', 'package-lock.json',
    'dist/index.js', 'dist/npm-scripts/verify-ripgrep.js',
    'dist/build-provenance.json',
  ];
  if (seen.size !== expected.size ||
      (m.nativeCapabilityAddon !== undefined && !expected.has(m.nativeCapabilityAddon)) ||
      requiredFiles.some(name => expected.get(name.toLowerCase())?.path !== name)) {
    throw new Error('Incomplete portable candidate inventory');
  }
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as
    { private?: unknown; version?: unknown };
  const provenance = parseRuntimeBuildIdentity(JSON.parse(
    await readFile(join(root, 'dist/build-provenance.json'), 'utf8')));
  if (pkg.private !== true || provenance.kind !== 'git' ||
      provenance.workspaceClean !== true || provenance.sourceCommit !== m.sourceCommit ||
      provenance.packageVersion !== pkg.version) {
    throw new Error('Portable build provenance mismatch');
  }
  return { result: 'PASS', target, fileCount: m.fileCount, releaseEligible: false };
}

export async function runPortableDoctor(args: readonly string[]): Promise<void> {
  if (args.length !== 1 || args[0] !== 'doctor') {
    process.stderr.write('Usage: desktop-commander portable doctor\n');
    process.exitCode = 1;
    return;
  }
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const root = join(here, '..', '..');
    const result = await inspectPortableCandidate(root);
    process.stdout.write(JSON.stringify(result) + '\n');
  } catch {
    // Never leak private paths, manifests or profile data in diagnostics.
    process.stderr.write('Portable candidate verification failed.\n');
    process.exitCode = 1;
  }
}
