import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile, mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { validateInstallerInput } from '../scripts/validate-installer-input.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sha = 'b'.repeat(40);
const valid = (target = 'win32-x64') => ({
  pkg: { name: '@roymejia2217/jame-desktop-commander', version: '0.2.52', private: true },
  manifest: { schemaVersion: 1, releaseEligible: false,
    kind: 'unpublished-portable-node-candidate', target, sourceCommit: sha,
    entrypoint: 'dist/index.js',
    runtimeExecutable: target === 'win32-x64' ? 'runtime/node.exe' : 'runtime/node',
    fileCount: 3, files: [
      { path: 'dist/index.js' }, { path: 'candidate-manifest.json' },
      { path: target === 'win32-x64' ? 'runtime/node.exe' : 'runtime/node' },
    ] },
  target, expectedCommit: sha,
});
test('candidate installer input retains provenance and denies unsafe alterations', () => {
  for (const target of ['win32-x64','linux-x64']) {
    const fixture = valid(target);
    assert.deepEqual(validateInstallerInput(fixture), { version:'0.2.52',target,sourceCommit:sha });
    for (const mutate of [
      x => { x.manifest.releaseEligible = true; },
      x => { x.manifest.sourceCommit = '0'.repeat(40); },
      x => { x.manifest.target = 'linux-arm64'; },
      x => { x.manifest.files[0].path = '../../outside'; },
      x => { x.manifest.files.push({ path:'native/jdc-capability-probe.node' }); },
      x => { x.pkg.private = false; },
    ]) {
      const other = structuredClone(fixture);
      mutate(other);
      assert.throws(() => validateInstallerInput(other));
    }
  }
});
test('installer provenance rejects N-API addons at any candidate path, not just native/', () => {
  for (const target of ['win32-x64', 'linux-x64']) {
    for (const path of [
      'native/jdc-capability-probe.node',
      'dist/plugins/ffi-payload.node',
      'node_modules/suspicious/build/Release/bridge.NODE',
    ]) {
      const input = valid(target);
      input.manifest.files.push({ path });
      // Keep the manifest count truthful: rejection must be due to the addon
      // itself, not a stale fileCount masking an unsafe payload.
      input.manifest.fileCount = input.manifest.files.length;
      assert.throws(
        () => validateInstallerInput(input),
        /Blocked .*native|Blocked .*addon/,
        `Expected explicit native addon denial for ${target}: ${path}`,
      );
    }
  }
});

test('installer admits only pinned platform runtime dependency addons', () => {
  const approved = {
    'win32-x64': 'node_modules/@img/sharp-win32-x64/lib/sharp-win32-x64-0.35.5.node',
    'linux-x64': 'node_modules/@img/sharp-linux-x64/lib/sharp-linux-x64-0.35.5.node',
  };
  for (const [target, path] of Object.entries(approved)) {
    const input = valid(target);
    input.manifest.files.push({ path });
    input.manifest.fileCount = input.manifest.files.length;
    assert.deepEqual(validateInstallerInput(input), {
      version: '0.2.52', target, sourceCommit: sha,
    });
  }
});

test('Windows installer stays per-user with separate launcher and no service takeover', async () => {
  const iss = await readFile(resolve(root,'packaging/windows/JameDesktopCommander.iss'),'utf8');
  const cmd = await readFile(resolve(root,'packaging/windows/jdc.cmd'),'utf8');
  assert.match(iss, /PrivilegesRequired=lowest/);
  assert.match(iss, /DefaultDirName=\{localappdata\}/);
  assert.match(iss, /Source:.*InputDir/);
  assert.doesNotMatch(iss,/\[(Run|Registry|Services)\]/i);
  assert.match(cmd, /runtime\\node\.exe/);
  assert.match(cmd, /dist\\index\.js/);
});
test('portable round-trip retrieves the exact immutable artifact uploaded in the same job', async () => {
  const workflow = await readFile(resolve(root, '.github/workflows/distribution-candidate.yml'), 'utf8');
  const upload = workflow.split('name: Retain unpublished candidate as a short-lived CI artifact')[1]
    ?.split('name: Download original uploaded candidate for round-trip acceptance')[0];
  const download = workflow.split('name: Download original uploaded candidate for round-trip acceptance')[1]
    ?.split('name: Verify downloaded TAR and smoke extracted native runtime')[0];
  assert.ok(upload && download, 'both original upload and identity-bound round-trip must be present');
  assert.match(upload, /^\s+id: portable_tar_upload\s*$/m);
  assert.match(download, /artifact-ids:\s*\$\{\{\s*steps\.portable_tar_upload\.outputs\.artifact-id\s*\}\}/);
  assert.match(download, /^\s+merge-multiple:\s*true\s*$/m,
    'the single exact-ID artifact must extract directly into the existing round-trip path');
  assert.doesNotMatch(download, /^\s+name:\s*UNPUBLISHED-jdc-portable-/m,
    'do not resolve an immutable just-uploaded artifact by eventual-consistency name search');
  assert.ok(download.includes('path: ${{ runner.temp }}/jdc-roundtrip-download/'));
});

test('Windows hosted installer checks full registered package lifecycle, not only GUI files', async () => {
  const workflow = await readFile(resolve(root,'.github/workflows/distribution-candidate.yml'),'utf8');
  const windows = workflow.split('name: Verify Windows installer install and uninstall')[1]
    ?.split('name: Build nFPM Debian installer candidate')[0];
  assert.ok(windows, 'real Windows installer acceptance job must remain present');
  assert.match(windows, /windows-installer-acceptance-runner[.]ps1/);
  const lifecycle = await readFile(resolve(root,'test/security/windows-installer-acceptance.ps1'),'utf8');
  for (const required of [
    'Installed JDC uninstall registration missing',
    'JDC uninstall registration remains after uninstall',
    'Windows launcher shortcut remains after uninstall',
    'Installed Node runtime remains after uninstall',
    'Bundled tunnel client remains after uninstall',
    'Installer directory remains after uninstall',
    'Unexpected JDC Scheduled Task added by installer',
  ]) {
    assert.ok(lifecycle.includes(required), `Missing executable Windows installer gate: ${required}`);
  }
});

test('packaged lifecycle denies residual startup, environment, firewall and owned processes', async () => {
  const workflow = await readFile(resolve(root,'.github/workflows/distribution-candidate.yml'),'utf8');
  const windows = workflow.split('name: Verify Windows installer install and uninstall')[1]
    ?.split('name: Build nFPM Debian installer candidate')[0];
  const linux = workflow.split('name: Verify Debian install and remove')[1]
    ?.split('name: Retain unpublished installer candidates')[0];
  assert.ok(windows && linux, 'both real OS lifecycle acceptance steps are required');
  assert.match(windows, /windows-installer-acceptance-runner[.]ps1/);
  const lifecycle = await readFile(resolve(root,'test/security/windows-installer-acceptance.ps1'),'utf8');
  // Fail-closed detection must classify private registry changes without
  // logging registry value names or startup command lines.
  assert.ok(lifecycle.includes('Get-RegistrySnapshotDetail -Key $key'));
  assert.ok(lifecycle.includes('Get-RegistryChangeSummary -Before'));
  assert.ok(lifecycle.includes('test-windows-installer-registry-drift-evidence.ps1'));
  for (const contract of [
    'Windows startup registry drift during installer acceptance (cause unverified)',
    'Windows environment registration modified by installer',
    'JDC process remains after uninstall',
  ]) assert.ok(lifecycle.includes(contract), `Missing native Windows residual gate: ${contract}`);
  for (const contract of [
    'sudo dpkg --purge jame-desktop-commander',
    'Pre-existing Linux systemd-user configuration modified',
    'Pre-existing Linux environment configuration modified',
    'Linux application directory remains after remove',
    'Debian package remains registered after purge',
    'Debian package has unreviewed maintainer hooks',
    'Linux installed process remains after package lifecycle',
  ]) assert.ok(linux.includes(contract), `Missing native Linux residual gate: ${contract}`);
});

test('Windows installer acceptance uses a real isolated non-admin profile and preserves fail-closed evidence', async () => {
  const workflow = await readFile(resolve(root,'.github/workflows/distribution-candidate.yml'),'utf8');
  const runner = await readFile(resolve(root,'test/security/windows-installer-acceptance-runner.ps1'),'utf8');
  const lifecycle = await readFile(resolve(root,'test/security/windows-installer-acceptance.ps1'),'utf8');
  assert.match(workflow, /windows-installer-acceptance-runner[.]ps1/);
  for (const expected of [
    'New-LocalUser', '-Credential', '-LoadUserProfile', 'Remove-LocalUser',
    'Get-LocalGroupMember', 'RUNNER_ENVIRONMENT', 'github-hosted',
  ]) assert.ok(runner.includes(expected), 'Missing isolated runner control: ' + expected);
  assert.match(lifecycle, /WindowsIdentity\]::GetCurrent/);
  assert.match(lifecycle, /ExpectedSid/);
  assert.match(lifecycle, /ProfileList/);
  assert.match(lifecycle, /User Shell Folders/);
  assert.match(lifecycle, /ExpandEnvironmentVariables/);
  assert.match(lifecycle, /Assert-HostPackageBoundary/);
  assert.match(lifecycle, /Get-RegistryChangeSummary/);
  assert.match(lifecycle, /Get-StartupFilesSnapshot/);
  const firewall = await readFile(resolve(root,'test/security/windows-installer-firewall-snapshot.ps1'),'utf8');
  assert.match(firewall, /Get-FirewallSnapshot/);
  assert.match(runner, /Get-FirewallSnapshot/);
});

test('isolated Windows installer failures disclose only fixed phase codes, not user paths or registry values', async () => {
  const runner = await readFile(resolve(root,'test/security/windows-installer-acceptance-runner.ps1'),'utf8');
  const lifecycle = await readFile(resolve(root,'test/security/windows-installer-acceptance.ps1'),'utf8');
  assert.match(runner, /E_INSTALLER_ACCEPTANCE_PHASE_/);
  assert.match(runner, /Get-Content -LiteralPath \$stdout/);
  assert.match(runner, /\^E_INSTALLER_ACCEPTANCE_PHASE_/);
  assert.doesNotMatch(runner, /Write-Output \$stderr|Write-Output \$_[.]Exception/);
  for (const phase of ['PROFILE', 'BASELINE', 'BASELINE_REGISTRY_TESTS',
                       'BASELINE_REGISTRY_STARTUP', 'BASELINE_STARTUP_FILES',
                       'BASELINE_ENVIRONMENT', 'BASELINE_FIREWALL', 'BASELINE_TASKS',
                       'BASELINE_SERVICES', 'BASELINE_SENTINEL',
                       'INSTALL', 'INSTALLED_ASSERTIONS', 'UNINSTALL', 'UNINSTALLED_ASSERTIONS']) {
    assert.match(lifecycle, new RegExp('E_INSTALLER_ACCEPTANCE_PHASE_' + phase));
  }
  assert.match(lifecycle, /trap \{/);
  assert.match(lifecycle, /Console\]::Error\.WriteLine/);
});

test('installer firewall observer executes three real host snapshots behind restricted Windows event fences', async () => {
  const runner = await readFile(resolve(root,'test/security/windows-installer-acceptance-runner.ps1'),'utf8');
  const lifecycle = await readFile(resolve(root,'test/security/windows-installer-acceptance.ps1'),'utf8');
  const firewall = await readFile(resolve(root,'test/security/windows-installer-firewall-snapshot.ps1'),'utf8');
  assert.match(runner, /EventWaitHandleAcl/);
  assert.match(runner, /EventWaitHandleSecurity/);
  assert.match(runner, /New-BoundEvent \$signalName.*Modify/);
  assert.match(runner, /New-BoundEvent \$resumeName.*Synchronize/);
  assert.match(runner, /Get-FirewallSnapshot/);
  assert.match(runner, /WaitOne\(/);
  assert.match(runner, /E_INSTALLER_FIREWALL_.*(TIMEOUT|DRIFT)/);
  assert.match(runner, /'BASELINE', 'INSTALLED', 'UNINSTALLED'/);
  assert.match(runner, /-FirewallSignalEvent/);
  assert.match(runner, /-FirewallResumeEvent/);
  assert.match(lifecycle, /Wait-ForHostFirewallObserver/);
  assert.equal((lifecycle.match(/^Wait-ForHostFirewallObserver$/gm) || []).length, 3);
  assert.doesNotMatch(lifecycle, /Get-NetFirewallRule|Get-FirewallSnapshot|\$firewallBefore/);
  for (const query of ['Get-NetFirewallRule', 'Get-NetFirewallPortFilter',
                       'Get-NetFirewallApplicationFilter', 'PersistentStore']) {
    assert.match(firewall, new RegExp(query));
  }
});

test('an early installer child failure yields only a fixed phase code', {
  skip: process.platform !== 'win32',
}, async () => {
  const runner = await readFile(resolve(root,'test/security/windows-installer-acceptance-runner.ps1'),'utf8');
  const fn = runner.match(/^function Write-SanitizedChildEvidence \{[\s\S]*?^\}/m)?.[0];
  assert.ok(fn, 'a single sanitized diagnostic function must handle early exits');
  assert.match(runner, /if \(\$child[.]HasExited\)/);
  assert.match(runner, /Write-SanitizedChildEvidence -ErrorPath \$stderr/);
  const dir = await mkdtemp(join(tmpdir(), 'jdc-installer-evidence-'));
  try {
    const evidence = join(dir, 'stderr.txt');
    await writeFile(evidence, 'E_INSTALLER_ACCEPTANCE_PHASE_INSTALL\n' +
      'E_INSTALLER_INNO_EXIT_CODE_7\nSECRET_CANARY_PRIVATE_PATH\n');
    const script = [fn, "Write-SanitizedChildEvidence -ErrorPath '" +
      evidence.replaceAll("'", "''") + "'"].join('\n');
    const result = spawnSync('powershell.exe', ['-NoProfile','-NonInteractive','-Command',script],
      {encoding:'utf8',timeout:12000});
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /E_INSTALLER_ACCEPTANCE_PHASE_INSTALL/);
    assert.match(result.stdout, /E_INSTALLER_INNO_EXIT_CODE_7/);
    assert.doesNotMatch(result.stdout + result.stderr, /SECRET_CANARY/);
  } finally { await rm(dir,{recursive:true,force:true}); }
});

test('isolated installer binds writable TEMP and TMP to the verified profile, not runner admin', {
  skip: process.platform !== 'win32',
}, async () => {
  const lifecycle = await readFile(resolve(root,'test/security/windows-installer-acceptance.ps1'),'utf8');
  const helper = lifecycle.match(/^function Set-VerifiedProfileTemporaryDirectory \{[\s\S]*?^\}/m)?.[0];
  assert.ok(helper, 'Missing tested profile-temp initialization');
  assert.match(lifecycle, /Set-VerifiedProfileTemporaryDirectory -Profile \$profile -LocalAppData \$expectedLocal/);
  const rootDir = await mkdtemp(join(tmpdir(), 'jdc-isolated-temp-fixture-'));
  try {
    const profile = join(rootDir,'user');
    const local = join(profile,'AppData','Local');
    await mkdir(local,{recursive:true});
    const q = value => value.replaceAll("'", "''");
    const ps = [helper,
      "$env:TEMP = 'C:\\Windows\\Temp\\inherited-host'",
      "$env:TMP = 'C:\\Windows\\Temp\\inherited-host'",
      "Set-VerifiedProfileTemporaryDirectory -Profile '" + q(profile) +
        "' -LocalAppData '" + q(local) + "'",
      "if ($env:TEMP -cne (Join-Path '" + q(local) + "' 'Temp') -or " +
        "$env:TMP -cne $env:TEMP -or !(Test-Path -LiteralPath $env:TEMP -PathType Container)) " +
        "{ throw 'TEMP_NOT_BOUND_TO_VERIFIED_PROFILE' }",
      "Write-Output 'ISOLATED_TEMP_BINDING_PASS'",
    ].join('\n');
    const result = spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',ps],
      {encoding:'utf8',timeout:12000});
    assert.equal(result.status,0,result.stderr);
    assert.match(result.stdout,/ISOLATED_TEMP_BINDING_PASS/);
    const negative = spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',
      [helper,"Set-VerifiedProfileTemporaryDirectory -Profile '" +
        q(profile) + "' -LocalAppData '" + q(rootDir) + "'"].join('\n')],
      {encoding:'utf8',timeout:12000});
    assert.notEqual(negative.status,0,'outside the verified profile must fail closed');
  } finally { await rm(rootDir,{recursive:true,force:true}); }
});

test('real Inno exit status is disclosed as a bounded numeric code without installation secrets', {
  skip: process.platform !== 'win32',
}, async () => {
  const lifecycle = await readFile(resolve(root,'test/security/windows-installer-acceptance.ps1'),'utf8');
  const runner = await readFile(resolve(root,'test/security/windows-installer-acceptance-runner.ps1'),'utf8');
  const helper = lifecycle.match(/^function Assert-InnoInstallerExitCode \{[\s\S]*?^\}/m)?.[0];
  assert.ok(helper, 'Inno exit status must not be reduced to phase-only evidence');
  assert.match(runner, /E_INSTALLER_INNO_EXIT_CODE_/);
  const reject = spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',
    [helper,'Assert-InnoInstallerExitCode -ExitCode 7'].join('\n')],
    {encoding:'utf8',timeout:12000});
  assert.equal(reject.status,1);
  assert.match(reject.stderr,/E_INSTALLER_INNO_EXIT_CODE_7/);
  const accept = spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',
    [helper,'Assert-InnoInstallerExitCode -ExitCode 0'].join('\n')],
    {encoding:'utf8',timeout:12000});
  assert.equal(accept.status,0,accept.stderr);
});

test('Debian package uses declarative nFPM, not custom dpkg assembly', async () => {
  const config = await readFile(resolve(root,'packaging/linux/nfpm.yaml'),'utf8');
  const launch = await readFile(resolve(root,'packaging/linux/jdc'),'utf8');
  assert.match(config, /name: jame-desktop-commander/);
  assert.match(config, /version: \$\{JDC_INSTALLER_VERSION\}/);
  assert.match(config, /type: tree\s+expand: true/,
    'nFPM requires explicit environment expansion for candidate source paths');
  assert.match(config, /dst: \/opt\/jame-desktop-commander/);
  assert.match(config, /dst: \/usr\/bin\/jdc/);
  assert.doesNotMatch(config, /scripts:|postinstall:|systemctl|curl .*\| *sh/);
  assert.match(launch, /exec \/opt\/jame-desktop-commander\/runtime\/node/);
  assert.match(launch, /"\$@"/);
});
test('existing candidate workflow builds EXE and DEB without publishing release', async () => {
  const workflow = await readFile(resolve(root,'.github/workflows/distribution-candidate.yml'),'utf8');
  assert.match(workflow, /Verify installer provenance/);
  assert.match(workflow, /Compile Inno Setup installer candidate/);
  assert.match(workflow, /Build nFPM Debian installer candidate/);
  assert.doesNotMatch(workflow, /export JDC_INSTALLER_VERSION=\\?"\\?\$\(/,
    'nFPM version assignment must not mask a failing Node command');
  assert.match(workflow, /Verify Windows installer install and uninstall/);
  assert.match(workflow, /Verify Debian install and remove/);
  assert.match(workflow, /upload-artifact@/);
  assert.doesNotMatch(workflow, /gh release upload|npm publish/);
});
test('Release Please retains exclusive gated release versioning', async () => {
  const config = await readFile(resolve(root,'release-please-config.json'),'utf8');
  const workflow = await readFile(resolve(root,'.github/workflows/release.yml'),'utf8');
  assert.match(config, /"release-type": "node"/);
  assert.match(workflow, /googleapis\/release-please-action@/);
  for (const issue of [124,139,148]) assert.match(workflow, new RegExp('\\b'+issue+'\\b'));
  assert.match(workflow, /JDC_PRODUCTION_RELEASE_APPROVED/);
});
test('Windows CLI accepts equivalent absolute source paths with forward slashes', {
  skip: process.platform !== 'win32',
}, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'jdc-installer-cli-'));
  try {
    const values = valid();
    await writeFile(join(dir, 'package.json'), JSON.stringify(values.pkg));
    await writeFile(join(dir, 'candidate-manifest.json'), JSON.stringify(values.manifest));
    const command = spawnSync(process.execPath, [
      resolve(root, 'scripts/validate-installer-input.mjs'),
      dir.replaceAll('\\', '/'),
      'win32-x64',
      values.expectedCommit,
    ], { encoding: 'utf8', timeout: 10000 });
    assert.equal(command.status, 0, command.stderr);
    assert.match(command.stdout, /"result":"PASS"/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
