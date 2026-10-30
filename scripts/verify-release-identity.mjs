// Fail-closed identity check for Release Please. Not an artifact attestation.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function refuse(reason) {
  throw new Error('E_RELEASE_IDENTITY_' + reason);
}

function validRepositoryUrl(value, repository) {
  if (typeof value !== 'string') return false;
  const accepted = [
    'https://github.com/' + repository,
    'https://github.com/' + repository + '.git',
  ];
  return accepted.includes(value);
}

export function verifyReleaseIdentity({ pkg, server, manifest, expectedRepository }) {
  if (typeof expectedRepository !== 'string' ||
      !/^[-\w]+\/[-\w]+$/.test(expectedRepository)) refuse('REPO_ARGUMENT');
  const [owner] = expectedRepository.split('/');
  if (!pkg || !server || !manifest || typeof pkg !== 'object' ||
      typeof server !== 'object' || typeof manifest !== 'object') {
    refuse('MISSING_METADATA');
  }
  if (!validRepositoryUrl(pkg.repository?.url, expectedRepository) ||
      !validRepositoryUrl(server.repository?.url, expectedRepository)) {
    refuse('FOREIGN_REPOSITORY');
  }
  if (typeof pkg.name !== 'string' ||
      !pkg.name.startsWith('@' + owner + '/') ||
      !/^@[a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*$/.test(pkg.name)) {
    refuse('UNOWNED_PACKAGE_NAME');
  }
  if (typeof server.name !== 'string' ||
      !server.name.startsWith('io.github.' + owner + '/') ||
      pkg.mcpName !== server.name) refuse('MCP_IDENTITY_MISMATCH');
  if (typeof pkg.version !== 'string' ||
      !/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(pkg.version) ||
      server.version !== pkg.version || manifest['.'] !== pkg.version) {
    refuse('VERSION_MISMATCH');
  }
  if (!Array.isArray(server.packages) || server.packages.length === 0 ||
      pkg.private !== false) refuse('REGISTRY_NOT_PUBLISHABLE');
  for (const entry of server.packages) {
    if (entry?.registryType !== 'npm' || entry?.identifier !== pkg.name ||
        entry?.version !== pkg.version) refuse('REGISTRY_IDENTITY_MISMATCH');
  }
  return true;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const expectedRepository = process.env.GITHUB_REPOSITORY;
    if (expectedRepository !== 'roymejia2217/JameDesktopCommander') {
      refuse('UNTRUSTED_CI_REPOSITORY');
    }
    const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
    const server = JSON.parse(readFileSync('server.json', 'utf8'));
    const manifest = JSON.parse(readFileSync('.release-please-manifest.json', 'utf8'));
    verifyReleaseIdentity({ pkg, server, manifest, expectedRepository });
    process.stdout.write('JDC_RELEASE_IDENTITY_ACCEPTED\n');
  } catch (error) {
    process.stderr.write('Release blocked: ' + error.message + '\n');
    process.exitCode = 1;
  }
}
