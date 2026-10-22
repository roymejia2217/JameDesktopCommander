import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { access, lstat, mkdir, readFile, realpath, stat, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import YAML from 'yaml';

export const LINUX_TUNNEL_UNIT = 'jame-desktop-commander-tunnel.service';
const marker = '# Managed by JameDesktopCommander Linux tunnel lifecycle v1';
const namePattern = /^[A-Za-z0-9._-]+$/;
const unitExec = /^ExecStart="([^"]+)" run --profile-dir "([^"]+)" --profile "([A-Za-z0-9._-]+)"$/m;

export interface LinuxTunnelDependencies {
  platform?: NodeJS.Platform;
  uid?: () => number;
  home?: string;
  run?: (executable: string, args: readonly string[]) => Promise<string>;
}

export interface LinuxTunnelStatus {
  unit: string;
  active: boolean;
  enabled: boolean;
  healthy: boolean;
  controlPlanePoll: boolean;
}

const defaultRun = (executable: string, args: readonly string[]): Promise<string> =>
  new Promise((resolve, reject) => {
    execFile(executable, [...args], {
      shell: false, encoding: 'utf8', timeout: 10000, maxBuffer: 65536,
    }, (error, stdout) => error ? reject(new Error(executable + ' operation failed')) : resolve(stdout));
  });

function safePath(value: string): string {
  if (!path.posix.isAbsolute(value) || /[%$"\\\u0000-\u001f\u007f]/.test(value)) {
    throw new Error('Linux tunnel paths must be absolute and contain no systemd substitutions or control characters.');
  }
  return path.posix.normalize(value);
}

function requireLinux(deps: LinuxTunnelDependencies): void {
  if ((deps.platform ?? process.platform) !== 'linux' || (deps.uid ?? process.getuid)?.() === 0) {
    throw new Error('Linux tunnel requires an unprivileged Linux user.');
  }
}

function parseOptions(args: readonly string[]): { executable: string; profileDir: string; profile: string } {
  let executable: string | undefined;
  let profileDir: string | undefined;
  let profile: string | undefined;
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i];
    const value = args[i + 1];
    if (!value || value.startsWith('--')) throw new Error('Missing Linux tunnel option value.');
    if (key === '--tunnel-client-bin' && !executable) executable = value;
    else if (key === '--profile-dir' && !profileDir) profileDir = value;
    else if (key === '--profile' && !profile) profile = value;
    else throw new Error('Unsupported or duplicated Linux tunnel option.');
  }
  if (!executable || !profileDir || !profile || !namePattern.test(profile)) {
    throw new Error('Linux install requires --tunnel-client-bin, --profile-dir and a valid --profile.');
  }
  return { executable: safePath(executable), profileDir: safePath(profileDir), profile };
}

export function buildLinuxTunnelUnit(executable: string, profileDir: string, profile: string): string {
  const bin = safePath(executable);
  const directory = safePath(profileDir);
  if (!namePattern.test(profile)) throw new Error('Invalid Linux tunnel profile name.');
  return [
    marker, '[Unit]', 'Description=JameDesktopCommander authenticated user tunnel',
    'After=network-online.target', 'Wants=network-online.target', '',
    '[Service]', 'Type=exec',
    'ExecStart="' + bin + '" run --profile-dir "' + directory + '" --profile "' + profile + '"',
    'Restart=on-failure', 'RestartSec=10s',
    'NoNewPrivileges=yes', 'UMask=0077', 'PrivateTmp=yes',
    'StandardOutput=journal', 'StandardError=journal', '',
    '[Install]', 'WantedBy=default.target', '',
  ].join('\n');
}

function unitPath(home: string): string {
  return path.join(safePath(home), '.config', 'systemd', 'user', LINUX_TUNNEL_UNIT);
}

// Recovery is authorized by a JDC marker and protected user-owned file.
// It does NOT grant permission to execute altered service content.
async function readOwnedManagedUnit(home: string): Promise<string> {
  const file = unitPath(home);
  const metadata = await lstat(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() ||
      metadata.uid !== (process.getuid?.() ?? -1) || (metadata.mode & 0o022)) {
    throw new Error('Linux tunnel unit has unsafe ownership, file type or permissions.');
  }
  const content = await readFile(file, 'utf8');
  if (!content.startsWith(marker + '\n')) throw new Error('Linux tunnel unit is not JDC-managed.');
  return content;
}

async function unitRegistration(home: string): Promise<{ executable: string; profileDir: string; profile: string }> {
  const content = await readOwnedManagedUnit(home);
  const match = unitExec.exec(content);
  if (!match || content.match(/^ExecStart=/gm)?.length !== 1) {
    throw new Error('Linux tunnel unit has an invalid execution contract.');
  }
  // A marker and one plausible ExecStart are insufficient: extra systemd
  // directives could execute additional programs under this user account.
  // Only the exact versioned template written by this lifecycle is trusted.
  if (content !== buildLinuxTunnelUnit(match[1], match[2], match[3])) {
    throw new Error('Linux tunnel unit differs from the managed template.');
  }
  return { executable: safePath(match[1]), profileDir: safePath(match[2]), profile: match[3] };
}

// systemd merges manager-selected fragments and drop-ins across its entire
// unit search path. Trust the *loaded* manager metadata, not a file scan.
async function assertTrustedLoadedUnit(
  home: string,
  systemctl: (args: readonly string[]) => Promise<string>,
): Promise<void> {
  const output = await systemctl([
    'show', LINUX_TUNNEL_UNIT,
    '--property=FragmentPath',
    '--property=DropInPaths',
    '--property=LoadState',
    '--property=NeedDaemonReload',
    '--no-pager',
  ]);
  const expectedKeys = new Set(['FragmentPath', 'DropInPaths', 'LoadState', 'NeedDaemonReload']);
  const props = new Map<string, string>();
  for (const line of output.trimEnd().split('\n')) {
    const idx = line.indexOf('=');
    const key = line.slice(0, idx);
    if (idx < 1 || !expectedKeys.has(key) || props.has(key)) {
      throw new Error('Linux tunnel effective systemd unit metadata is invalid.');
    }
    props.set(key, line.slice(idx + 1));
  }
  const fragment = await realpath(unitPath(home));
  // Fail closed if configuration is stale or another fragment/drop-in is
  // loaded. No untrusted manager paths are copied to logs or CLI errors.
  if (props.size !== expectedKeys.size ||
      props.get('FragmentPath') !== fragment ||
      props.get('DropInPaths') !== '' ||
      props.get('LoadState') !== 'loaded' ||
      props.get('NeedDaemonReload') !== 'no') {
    throw new Error('Linux tunnel effective systemd unit differs from the managed definition.');
  }
}

async function ensureUserDirectory(home: string, create = true): Promise<void> {
  const resolvedHome = await realpath(home);
  if (resolvedHome !== home) throw new Error('HOME must be its canonical directory.');
  for (const dir of [home, path.join(home, '.config'), path.join(home, '.config', 'systemd'),
    path.join(home, '.config', 'systemd', 'user')]) {
    if (create && dir !== home) await mkdir(dir, { mode: 0o700 }).catch((e: NodeJS.ErrnoException) => {
      if (e.code !== 'EEXIST') throw e;
    });
    const st = await lstat(dir);
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid?.()) {
      throw new Error('Linux tunnel configuration directory is not owned by the current user.');
    }
    // Ownership alone does not protect an OS unit from a different principal
    // allowed to write to one of its ancestor directories.
    if ((st.mode & 0o022) !== 0) {
      throw new Error('Linux tunnel configuration directory is writable by another principal.');
    }
  }
}

// Parse the manager's exact two-property response once. A regex presence
// check could accept contradictory or duplicated state declarations and
// wrongly report health or authorize try-restart.
function parseActivationState(response: string): { active: boolean; enabled: boolean } {
  const expected = new Set(['ActiveState', 'UnitFileState']);
  const entries = new Map<string, string>();
  const lines = (response.endsWith('\n') ? response.slice(0, -1) : response).split('\n');
  for (const line of lines) {
    const index = line.indexOf('=');
    const key = line.slice(0, index);
    const value = line.slice(index + 1);
    if (index < 1 || !expected.has(key) || entries.has(key) ||
        !value || value.trim() !== value) {
      throw new Error('Invalid Linux tunnel systemd activation state response.');
    }
    entries.set(key, value);
  }
  if (entries.size !== expected.size) {
    throw new Error('Invalid Linux tunnel systemd activation state response.');
  }
  return {
    active: entries.get('ActiveState') === 'active',
    enabled: entries.get('UnitFileState') === 'enabled',
  };
}

function healthFromJson(value: string): { healthy: boolean; controlPlanePoll: boolean } {
  const parsed: unknown = JSON.parse(value);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('Invalid tunnel health response.');
  const obj = parsed as Record<string, unknown>;
  function checked(key: string): boolean {
    const entry = obj[key];
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry) ||
        typeof (entry as Record<string, unknown>).ok !== 'boolean') throw new Error('Invalid health field ' + key);
    return (entry as { ok: boolean }).ok;
  }
  if (typeof obj.result !== 'string') throw new Error('Invalid tunnel result.');
  const poll = checked('control_plane_poll');
  return { healthy: obj.result === 'ok' && checked('healthz') && checked('readyz') && poll, controlPlanePoll: poll };
}

export async function runLinuxTunnelCommand(
  args: readonly string[],
  dependencies: LinuxTunnelDependencies = {},
): Promise<{ action: string; unit: string; status?: LinuxTunnelStatus }> {
  requireLinux(dependencies);
  const home = safePath(dependencies.home ?? process.env.HOME ?? '');
  const run = dependencies.run ?? defaultRun;
  const systemctl = (parts: readonly string[]) => run('systemctl', ['--user', ...parts]);
  const [action, ...options] = args;
  if (!['doctor', 'install', 'start', 'stop', 'restart', 'status', 'uninstall'].includes(action ?? '')) {
    throw new Error('Linux tunnel supports doctor, install, start, stop, restart, status and uninstall.');
  }
  // Do not mutate files when the user manager or DBus session is absent.
  await systemctl(['show-environment']);
  const unit = LINUX_TUNNEL_UNIT;
  if (action === 'install' || action === 'doctor') {
    const parsed = parseOptions(options);
    const executable = await realpath(parsed.executable);
    const profileDir = await realpath(parsed.profileDir);
    const binary = await stat(executable);
    if (!binary.isFile()) throw new Error('Tunnel executable must be a regular file.');
    await access(executable, constants.X_OK);
    if (!(await stat(profileDir)).isDirectory()) throw new Error('Tunnel profile directory unavailable.');
    await run(executable, ['doctor', '--profile-dir', profileDir, '--profile', parsed.profile, '--explain']);
    // A read-only JDC preflight must never create a unit or change its state.
    // The official client doctor owns its own diagnostic behavior.
    if (action === 'doctor') return { action, unit };
    await ensureUserDirectory(home);
    const unitFile = unitPath(home);
    await writeFile(unitFile, buildLinuxTunnelUnit(executable, profileDir, parsed.profile),
      { flag: 'wx', mode: 0o600 });
    // A failed reload leaves a disabled, JDC-managed unit for explicit uninstall.
    await systemctl(['daemon-reload']);
  } else {
    if (options.length) throw new Error('Linux tunnel action accepts no extra arguments.');
    const recovery = action === 'stop' || action === 'uninstall';
    // Verify every ancestor on executable/health paths before trusting the
    // owned unit. UNINSTALL also requires a protected parent to unlink safely.
    // STOP deliberately remains available when the parent is compromised:
    // disabling the fixed systemd unit name must not require deleting files.
    if (action !== 'stop') {
      await ensureUserDirectory(home, false);
    }
    // STOP/UNINSTALL must be available for an altered but still user-owned
    // JDC-marked unit. START/RESTART/STATUS require the exact executable
    // template and reject it if modified.
    const registration = recovery
      ? (await readOwnedManagedUnit(home), null)
      : await unitRegistration(home);
    // Never activate, conditionally restart, or claim health for a unit whose
    // manager-loaded definition differs from the sole JDC-owned fragment.
    // STOP and UNINSTALL remain available to recover a compromised service.
    if (action === 'start' || action === 'restart' || action === 'status') {
      await assertTrustedLoadedUnit(home, systemctl);
    }
    if (action === 'start') {
      await systemctl(['enable', '--now', unit]);
    } else if (action === 'restart') {
      // First reject an inactive/disabled unit; also use try-restart so
      // the systemd manager cannot revive a unit stopped after this check.
      const state = parseActivationState(await systemctl(['show', unit,
        '--property=ActiveState', '--property=UnitFileState', '--no-pager']));
      if (!state.active || !state.enabled) {
        throw new Error('Linux tunnel restart requires an enabled, active user service.');
      }
      // A successful restart does not establish remote control-plane readiness.
      await systemctl(['try-restart', unit]);
    } else if (action === 'stop' || action === 'uninstall') {
      await systemctl(['disable', '--now', unit]);
      if (action === 'uninstall') {
        await unlink(unitPath(home));
        await systemctl(['daemon-reload']);
      }
    } else if (action === 'status') {
      const { active, enabled } = parseActivationState(
        await systemctl(['show', unit, '--property=ActiveState', '--property=UnitFileState', '--no-pager']),
      );
      let health = { healthy: false, controlPlanePoll: false };
      if (active) {
        if (!registration) throw new Error('Linux tunnel registration unavailable.');
        const list = JSON.parse(await run(registration.executable,
          ['profiles', 'list', '--profile-dir', registration.profileDir, '--json'])) as unknown;
        if (!Array.isArray(list)) throw new Error('Invalid tunnel profiles list.');
        // The official client must identify one unambiguous profile.
        // Selecting the first match can report readiness for the wrong entry.
        const matches = list.filter((item) => typeof item === 'object' && item !== null &&
          !Array.isArray(item) && (item as { name?: unknown }).name === registration.profile);
        if (matches.length !== 1) throw new Error('Tunnel profile missing or ambiguous.');
        const entry = matches[0] as { path?: unknown };
        if (typeof entry.path !== 'string') throw new Error('Tunnel profile not found.');
        const profileFile = await realpath(safePath(entry.path));
        const profile = YAML.parse(await readFile(profileFile, 'utf8')) as { health?: { url_file?: unknown } };
        if (typeof profile?.health?.url_file !== 'string') throw new Error('Missing tunnel health URL reference.');
        const urlFile = safePath(profile.health.url_file);
        health = healthFromJson(await run(registration.executable,
          ['health', '--json', '--url-file', urlFile, '--require-control-plane-poll']));
      }
      return { action, unit, status: { unit, active, enabled, ...health } };
    }
  }
  return { action, unit };
}
