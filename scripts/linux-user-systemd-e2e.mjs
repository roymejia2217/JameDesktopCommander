// Real, disposable GitHub-hosted Ubuntu user-manager acceptance for the
// independently restored portable candidate. Uses a deterministic synthetic
// tunnel client: does NOT authenticate to the production control plane.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmod, lstat, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { pathToFileURL } from 'node:url';

if (process.platform !== 'linux' || process.getuid?.() === 0) {
  throw new Error('Real user-manager acceptance requires an unprivileged Linux host.');
}
const candidate = process.argv[2];
if (!candidate || !isAbsolute(candidate)) throw new Error('Expected an absolute restored candidate path.');
const { LINUX_TUNNEL_UNIT } = await import(
  pathToFileURL(join(candidate, 'dist/platform/linux/tunnel-lifecycle.js')).href
);
const manifest = JSON.parse(await readFile(join(candidate, 'candidate-manifest.json'), 'utf8'));
const runtime = join(candidate, manifest.runtimeExecutable);
assert.equal((await stat(runtime)).isFile(), true);
assert.doesNotMatch(runtime, /[\r\n ]/, 'Packaged Node runtime path must support an absolute shebang');
const entrypoint = join(candidate, manifest.entrypoint);
assert.equal((await stat(entrypoint)).isFile(), true);
const executeCli = (args, expectedStatus = 0) => {
  const result = spawnSync(runtime, [entrypoint, 'tunnel', ...args], {
    encoding: 'utf8', timeout: 20000, maxBuffer: 65536,
    env: { ...process.env, NODE_OPTIONS: '' },
  });
  assert.equal(result.error, undefined, 'Packaged Node CLI failed to launch');
  assert.equal(result.status, expectedStatus,
    'Unexpected packaged CLI exit status for action ' + args[0]);
  if (expectedStatus !== 0) return { error: result.stderr, stdout: result.stdout };
  return JSON.parse(result.stdout);
};

const userHome = homedir();
const unitFile = join(userHome, '.config/systemd/user', LINUX_TUNNEL_UNIT);
await assert.rejects(lstat(unitFile), { code: 'ENOENT' },
  'Never operate on an existing, potentially user-owned tunnel unit');

const workspace = await mkdtemp(join(userHome, '.jdc-ci-user-unit-'));
const profile = join(workspace, 'profile.yaml');
const bin = join(workspace, 'synthetic-tunnel-client');
const runUnit = (args) => execFileSync('systemctl', ['--user', ...args], {
  encoding: 'utf8', timeout: 10000, maxBuffer: 65536,
}).trim();
const fake = [
  '#!' + runtime,
  "import { join } from 'node:path';",
  'const args = process.argv.slice(2);',
  "if (args[0] === 'doctor') process.exit(0);",
  "if (args[0] === 'profiles' && args[1] === 'list') {",
  "  const i = args.indexOf('--profile-dir');",
  "  if (i < 0 || !args[i + 1]) process.exit(2);",
  "  process.stdout.write(JSON.stringify([{ name: 'ci', path: join(args[i + 1], 'profile.yaml') }]));",
  '  process.exit(0);',
  '}',
  "if (args[0] === 'health') {",
  "  process.stdout.write(JSON.stringify({result:'ok',healthz:{ok:true},readyz:{ok:true},control_plane_poll:{ok:true}}));",
  '  process.exit(0);',
  '}',
  "if (args[0] === 'run') { setInterval(() => {}, 1000); }",
  'else process.exit(2);',
  '',
].join('\n');

const pid = () => {
  const output = runUnit(['show', LINUX_TUNNEL_UNIT, '--property=MainPID', '--no-pager']);
  const match = /^MainPID=(\d+)$/m.exec(output);
  assert.ok(match, 'Missing systemd MainPID observation');
  const n = Number(match[1]);
  assert.ok(Number.isSafeInteger(n) && n > 0, 'The user manager did not launch a real process');
  process.kill(n, 0);
  return n;
};

let installed = false;
try {
  runUnit(['show-environment']);
  await writeFile(bin, fake, { mode: 0o700, flag: 'wx' });
  await chmod(bin, 0o700);
  await writeFile(profile, 'health:\n  url_file: "' + join(workspace, 'health.url') + '"\n',
    { mode: 0o600, flag: 'wx' });

  const options = ['install', '--tunnel-client-bin', bin,
    '--profile-dir', workspace, '--profile', 'ci'];
  assert.deepEqual(executeCli(['doctor', ...options.slice(1)]),
    { action: 'doctor', unit: LINUX_TUNNEL_UNIT });
  await assert.rejects(lstat(unitFile), { code: 'ENOENT' },
    'Pre-install doctor must not create the unit');
  assert.deepEqual(executeCli(options), { action: 'install', unit: LINUX_TUNNEL_UNIT });
  installed = true;
  assert.equal((await lstat(unitFile)).mode & 0o077, 0, 'Unit permissions must be private');
  execFileSync('systemd-analyze', ['--user', 'verify', unitFile],
    { encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });

  assert.deepEqual(executeCli(['start']), { action: 'start', unit: LINUX_TUNNEL_UNIT });
  const first = pid();
  assert.equal(executeCli(['status']).status?.active, true);
  assert.equal(executeCli(['status']).status?.enabled, true);
  // The synthetic health response verifies CLI parsing only. It is NOT a
  // network probe or evidence of authentication to an external service.
  assert.deepEqual(executeCli(['restart']), { action: 'restart', unit: LINUX_TUNNEL_UNIT });
  const second = pid();
  assert.notEqual(second, first, 'A real systemd restart must create a fresh process');
  assert.deepEqual(executeCli(['stop']), { action: 'stop', unit: LINUX_TUNNEL_UNIT });
  assert.equal(JSON.parse(executeCli(['status'], 1).stdout).status?.active, false);
  assert.match(executeCli(['restart'], 1).error, /enabled, active/);
  runUnit(['try-restart', LINUX_TUNNEL_UNIT]);
  assert.equal(JSON.parse(executeCli(['status'], 1).stdout).status?.active, false,
    'Native try-restart must not revive a stopped service');
  console.log('Real Linux systemd user-service lifecycle: PASS (synthetic client; no remote authentication)');
} finally {
  try {
    if (installed) assert.deepEqual(executeCli(['uninstall']),
      { action: 'uninstall', unit: LINUX_TUNNEL_UNIT });
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}
