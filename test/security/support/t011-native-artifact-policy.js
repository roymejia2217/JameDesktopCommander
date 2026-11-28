// OC-07.2e: fail-closed, test-only guard for the existing public native artifact.
const ALLOWED = new Set([
  'native/capability-probe/Cargo.lock',
  'native/capability-probe/target/release/jdc-capability-probe.node',
]);

function reject(reason) {
  throw new Error('E_T011_ARTIFACT_POLICY: ' + reason);
}

// The only additional job is a mandatory, fresh Windows hosted runner
// with no job outputs, dependencies, permission override or artifact actions.
// Exact action/step inventory prevents an implicit artifact/cache handoff.
function validateIsolatedStorageJob(job) {
  const keys = ['name', 'runs-on', 'steps', 'timeout-minutes'];
  if (Object.keys(job).sort().join(',') !== keys.join(',') ||
      job['runs-on'] !== 'windows-2025' || job['timeout-minutes'] !== 30 ||
      !Array.isArray(job.steps)) {
    reject('isolated storage job boundary changed');
  }
  const ids = [
    'scm_storage_checkout', 'scm_storage_rust', 'scm_storage_node',
    'scm_storage_dependencies', 'scm_storage_runtime', 'scm_storage_default',
    'scm_storage_custody', 'scm_storage_native', 'windows_scm_admitted_storage',
  ];
  if (job.steps.map(step => step.id).join(',') !== ids.join(',')) {
    reject('isolated storage step inventory changed');
  }
  const [checkout, rust, node, dependencies, runtime, baseline, custody, native, acceptance] = job.steps;
  for (const step of job.steps) {
    const allowed = step === checkout || step === node
      ? ['id', 'name', 'uses', 'with'] : ['id', 'name', 'run', 'shell'];
    if (Object.keys(step).some(key => !allowed.includes(key))) {
      reject('isolated step configuration changed');
    }
  }
  const exactRef = '$' + '{{ github.event.pull_request.head.sha || github.sha }}';
  if (checkout.uses !== 'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803' ||
      checkout.with?.ref !== exactRef || checkout.with?.['persist-credentials'] !== false ||
      Object.keys(checkout.with).length !== 2 ||
      node.uses !== 'actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38' ||
      node.with?.['node-version'] !== 24 || node.with?.['package-manager-cache'] !== false ||
      Object.keys(node.with).length !== 2 ||
      rust.run !== 'rustup toolchain install 1.91.1 --profile minimal --component clippy' ||
      dependencies.run !== 'npm ci --ignore-scripts --no-audit --no-fund' ||
      runtime.run !== 'npm run build' ||
      baseline.run !== 'cargo +1.91.1 build --locked --manifest-path native/authority-service/Cargo.toml --bin jdc-authority-scm --bin jdc-authority-scm-issued-client' ||
      custody.run !== 'cargo +1.91.1 build --locked --examples --manifest-path native/authority-store/Cargo.toml') {
    reject('isolated storage toolchain or source custody changed');
  }
  // Check complete commands, not marker substrings that could be preceded
  // by exit 0 or followed by a suppressed native error.
  const cargo = 'cargo +1.91.1 ';
  const feature = ' --locked --features scm-storage-proof --manifest-path native/authority-service/Cargo.toml';
  const binary = ' --bin jdc-authority-scm-issued-proof';
  const checkExit = 'if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }';
  const expectedNative = [
    "$ErrorActionPreference = 'Stop'",
    cargo + 'clippy' + feature + ' --lib' + binary + ' -- -D warnings',
    checkExit,
    cargo + 'test' + feature + ' --lib' + binary,
    checkExit,
    cargo + 'build' + feature + binary,
    checkExit,
    '',
  ].join('\n');
  const expectedAcceptance = [
    "$ErrorActionPreference = 'Stop'",
    '$result = @(pwsh -NoProfile -File test/security/t011-windows-storage-domain-acceptance.ps1 -ScmStorageOnly)',
    '$code = $LASTEXITCODE',
    '$result | Write-Output',
    'if ($code -ne 0) { exit $code }',
    "if ($result -cnotcontains 'T011_WINDOWS_SCM_ADMITTED_SDK_MUTATIONS_PASS_NONRELEASE' -or",
    "    $result -cnotcontains 'T011_WINDOWS_SCM_ADMITTED_SDK_CANCEL_REPLAY_PASS_NONRELEASE' -or",
    "    $result -cnotcontains 'T011_WINDOWS_SCM_ADMITTED_OUTSIDE_INTEGRITY_PASS_NONRELEASE') {",
    "  throw 'E_STORAGE_SCM_ADMITTED_VERDICT_MISSING'",
    '}',
    '',
  ].join('\n');
  if (native.shell !== 'pwsh' || acceptance.shell !== 'pwsh' ||
      native.run !== expectedNative || acceptance.run !== expectedAcceptance) {
    reject('mandatory isolated storage acceptance changed');
  }
}

/**
 * Validate the reviewed artifact upload surface, not general CI secrecy.
 * Never parse/execute shell, expand globs, or infer approved paths.
 */
export function validateNativeArtifactPolicy(workflow) {
  const perms = workflow?.permissions;
  if (!perms || Object.keys(perms).length !== 1 || perms.contents !== 'read') {
    reject('workflow permissions must be contents:read only');
  }
  const jobs = workflow?.jobs;
  if (!jobs || Object.keys(jobs).length !== 2 || !jobs['native-probe'] ||
      !jobs['scm-storage-nonrelease']) {
    reject('unexpected workflow job');
  }
  validateIsolatedStorageJob(jobs['scm-storage-nonrelease']);
  const job = jobs['native-probe'];
  if (job.needs !== undefined) {
    reject('artifact producer must not depend on isolated research');
  }
  if (job.permissions !== undefined || !Array.isArray(job.steps)) {
    reject('job permission escalation or missing steps');
  }
  const uploads = job.steps.filter((step) =>
    typeof step?.uses === 'string' &&
    step.uses.startsWith('actions/upload-artifact@'));
  if (uploads.length !== 1) {
    reject('requires exactly one approved upload step');
  }
  const item = uploads[0];
  if (item.uses !== 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02') {
    reject('unexpected upload action revision');
  }
  const conf = item.with;
  if (!conf || typeof conf.path !== 'string' ||
      conf['retention-days'] !== 1 ||
      conf['if-no-files-found'] !== 'error' ||
      conf['compression-level'] !== 0) {
    reject('upload settings changed');
  }
  const name = 'UNPUBLISHED-t011-capability-probe-' + '$' + '{{ matrix.target }}';
  if (conf.name !== name) {
    reject('unexpected artifact identity');
  }
  const paths = conf.path.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
  if (paths.length !== ALLOWED.size ||
      new Set(paths).size !== ALLOWED.size ||
      paths.some((value) => !ALLOWED.has(value))) {
    reject('unapproved upload path');
  }
  return true;
}
