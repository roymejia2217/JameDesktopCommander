// OC-07.2f: repository-wide, test-only inventory of GitHub upload-artifact surfaces.
// This is a narrow policy, not a general secret-exfiltration scanner.
import { validateNativeArtifactPolicy } from './t011-native-artifact-policy.js';

const PINNED_UPLOAD = 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02';
const matrixTarget = '$' + '{{ matrix.target }}';
const candidatePath = '$' + '{{ runner.temp }}' +
  '/UNPUBLISHED-jdc-portable-' + matrixTarget + '.tar';
const installerPath = '$' + '{{ runner.temp }}' +
  '/jdc-installer-output/UNPUBLISHED-jdc-installer-' + matrixTarget +
  '.' + '$' + "{{ matrix.target == 'win32-x64' && 'exe' || 'deb' }}";

function reject(reason) {
  throw new Error('E_T011_PUBLIC_ARTIFACT: ' + reason);
}

// The GitHub-owned event commit is the PR test merge commit or main push SHA.
// All same-run producer/GUI/acceptor artifacts must bind to this one identity.
const SOURCE_SHA = '$' + '{{ github.sha }}';
const UI_STAGE = '$' + '{{ runner.temp }}' + '/jdc-operator-ui';
const LINUX_UI_STAGE = '$' + '{{ runner.temp }}' + '/jdc-operator-ui-linux';
const PINNED_DOWNLOAD = 'actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093';
const PINNED_CHECKOUT = 'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803';
const PINNED_NODE = 'actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38';

function validateOperatorUiArtifactPolicy(nativeUi, portable) {
  if (!nativeUi || nativeUi.on !== 'workflow_call' ||
      Object.keys(nativeUi.permissions ?? {}).length !== 1 ||
      nativeUi.permissions?.contents !== 'read') {
    reject('native UI workflow must be an unprivileged reusable source-locked build');
  }
  const job = nativeUi.jobs?.['native-gui'];
  const steps = job?.steps;
  if (!Array.isArray(steps) || job.permissions !== undefined ||
      job.if !== undefined || job.env?.JDC_CANDIDATE_SOURCE_SHA !== SOURCE_SHA ||
      job['runs-on'] !== 'windows-2025' ||
      job['continue-on-error'] !== undefined ||
      steps.some(step => step['continue-on-error'] !== undefined)) {
    reject('reviewed native UI build job identity or permissions changed');
  }
  const checkout = steps.find(step => step.name === 'Checkout exact native operator source');
  if (checkout?.uses !== PINNED_CHECKOUT || checkout.with?.ref !== SOURCE_SHA ||
      checkout.with?.['persist-credentials'] !== false) {
    reject('native UI source checkout must be immutable and credential-free');
  }
  const allowedActions = new Set([PINNED_CHECKOUT, PINNED_NODE, PINNED_UPLOAD]);
  if (steps.some(step => step.uses && !allowedActions.has(step.uses))) {
    reject('native UI workflow may not add unrelated external actions');
  }
  const buildIndex = steps.findIndex(step => step.name === 'Build pinned Windows operator UI');
  const uploadIndex = steps.findIndex(step => step.name ===
    'Retain immutable, unpublished native GUI overlay for candidate installation');
  const build = steps[buildIndex];
  const upload = steps[uploadIndex];
  if (buildIndex < 0 || uploadIndex <= buildIndex ||
      !build.run.includes('cargo +1.95.0 build --release --locked --manifest-path native/tunnel-operator-ui/Cargo.toml') ||
      !build.run.includes('operator-ui-bundle.mjs create') ||
      !build.run.includes('operator-ui-bundle.mjs verify') ||
      /native\/(?:capability-probe|authority-service)|research_impl|receiver-test-fixture/.test(build.run)) {
    reject('native UI build must verify an exact read-only frontend inventory');
  }
  const conf = upload.with;
  if (upload.uses !== PINNED_UPLOAD ||
      conf?.name !== 'UNPUBLISHED-jdc-operator-ui-win32-x64' ||
      conf?.path !== UI_STAGE + '/' ||
      conf?.['if-no-files-found'] !== 'error' ||
      conf?.['retention-days'] !== 1 ||
      conf?.['compression-level'] !== 0) {
    reject('native UI upload is not the narrowly reviewed short-lived overlay');
  }
  const caller = portable.jobs?.['windows-operator-ui'];
  const candidateJob = portable.jobs?.['portable-acceptance'];
  const download = candidateJob?.steps?.find(step =>
    step.name === 'Download exact Windows operator UI overlay');
  const inno = candidateJob?.steps?.find(step =>
    step.name === 'Compile Inno Setup installer candidate');
  if (caller?.uses !== './.github/workflows/windows-operator-ui-bundle.yml' ||
      caller.with !== undefined ||
      JSON.stringify(candidateJob?.needs) !==
        JSON.stringify(['portable-candidate', 'windows-operator-ui', 'linux-operator-ui']) ||
      download?.uses !== PINNED_DOWNLOAD ||
      download.if !== "matrix.target == 'win32-x64'" ||
      download.with?.name !== conf.name ||
      download.with?.path !== UI_STAGE ||
      !inno?.run?.includes('operator-ui-bundle.mjs verify')) {
    reject('native UI download must be same-run, source-bound and verified');
  }
}

function validateLinuxOperatorUiArtifactPolicy(nativeUi, portable) {
  if (!nativeUi || nativeUi.on !== 'workflow_call' ||
      Object.keys(nativeUi.permissions ?? {}).length !== 1 ||
      nativeUi.permissions?.contents !== 'read') {
    reject('Linux native GUI must remain a source-bound unprivileged build');
  }
  const job = nativeUi.jobs?.['native-gui'];
  const steps = job?.steps;
  if (job?.['runs-on'] !== 'ubuntu-24.04' ||
      !Array.isArray(steps) || job.permissions !== undefined ||
      job.if !== undefined || job.env?.JDC_CANDIDATE_SOURCE_SHA !== SOURCE_SHA ||
      job['continue-on-error'] !== undefined ||
      steps.some(step => step['continue-on-error'] !== undefined)) {
    reject('Linux native UI runner or failure handling changed');
  }
  const checkout = steps.find(step => step.name === 'Checkout exact native operator source');
  if (checkout?.uses !== PINNED_CHECKOUT || checkout.with?.ref !== SOURCE_SHA ||
      checkout.with?.['persist-credentials'] !== false ||
      steps.some(step => step.uses && ![PINNED_CHECKOUT, PINNED_NODE, PINNED_UPLOAD].includes(step.uses))) {
    reject('Linux operator source checkout or actions are untrusted');
  }
  const buildIndex = steps.findIndex(step =>
    step.name === 'Build pinned Linux operator UI with official Rust toolchain');
  const uploadIndex = steps.findIndex(step =>
    step.name === 'Retain exact unpublished Linux GUI overlay');
  const build = steps[buildIndex];
  const upload = steps[uploadIndex];
  if (buildIndex < 0 || uploadIndex <= buildIndex ||
      !build.run.includes('test "$(git rev-parse HEAD)" = "$JDC_CANDIDATE_SOURCE_SHA"') ||
      !build.run.includes('cargo +1.95.0 build --release --locked') ||
      !build.run.includes('epaint_default_fonts') ||
      !build.run.includes('foldhash') ||
      !build.run.includes('operator-ui-bundle.mjs create') ||
      !build.run.includes('operator-ui-bundle.mjs verify') ||
      !build.run.includes('linux-x64') ||
      /native\/(?:capability-probe|authority-service)|research_impl|receiver-test-fixture/.test(build.run)) {
    reject('Linux UI must build exact source and verify closed overlay inventory');
  }
  const conf = upload.with;
  if (upload.uses !== PINNED_UPLOAD ||
      conf?.name !== 'UNPUBLISHED-jdc-operator-ui-linux-x64' ||
      conf?.path !== LINUX_UI_STAGE + '/' ||
      conf?.['if-no-files-found'] !== 'error' ||
      conf?.['retention-days'] !== 1 ||
      conf?.['compression-level'] !== 0) {
    reject('Linux UI upload must be a narrowly reviewed one-day artifact');
  }
  const candidate = portable.jobs?.['portable-acceptance'];
  const caller = portable.jobs?.['linux-operator-ui'];
  const download = candidate?.steps?.find(step =>
    step.name === 'Download exact Linux operator UI overlay');
  const nfpm = candidate?.steps?.find(step =>
    step.name === 'Build nFPM Debian installer candidate');
  const install = candidate?.steps?.find(step => step.id === 'linux_installer_acceptance');
  if (caller?.uses !== './.github/workflows/linux-operator-ui-bundle.yml' ||
      caller.with !== undefined ||
      download?.uses !== PINNED_DOWNLOAD ||
      download.if !== "matrix.target == 'linux-x64'" ||
      download.with?.name !== conf.name ||
      download.with?.path !== LINUX_UI_STAGE ||
      nfpm?.env?.JDC_OPERATOR_UI_SOURCE !== LINUX_UI_STAGE ||
      !nfpm?.run?.includes('operator-ui-bundle.mjs verify') ||
      !nfpm?.run?.includes('linux-x64') ||
      !install?.run?.includes('operator-ui-bundle.mjs verify-installed') ||
      !install?.run?.includes('linux-x64') ||
      !install?.run?.includes('--check-installation') ||
      !install?.run?.includes('dpkg -r jame-desktop-commander')) {
    reject('Linux overlay must be same-run, installed, checked and uninstalled');
  }
}

/** Restrict the known official upload-artifact action throughout all workflows. */
export function validatePublicArtifactInventory(workflows) {
  if (!workflows || typeof workflows !== 'object' || Array.isArray(workflows)) {
    reject('expected parsed workflow mapping');
  }
  const native = workflows['t011-capability-feasibility.yml'];
  const portable = workflows['distribution-candidate.yml'];
  const nativeUi = workflows['windows-operator-ui-bundle.yml'];
  const linuxUi = workflows['linux-operator-ui-bundle.yml'];
  if (!native || !portable || !nativeUi || !linuxUi) {
    reject('mandatory reviewed workflows missing');
  }
  // Reuse the stronger dedicated, separately tested native artifact policy.
  try {
    validateNativeArtifactPolicy(native);
  } catch {
    reject('native upload must pass dedicated boundary');
  }

  const uploads = [];
  for (const [workflowName, doc] of Object.entries(workflows)) {
    if (!doc || typeof doc !== 'object' || !doc.jobs ||
        typeof doc.jobs !== 'object' || Array.isArray(doc.jobs)) {
      reject('invalid workflow jobs: ' + workflowName);
    }
    for (const [jobName, job] of Object.entries(doc.jobs)) {
      // Reusable jobs need not contain steps; they cannot use upload-artifact
      // directly. This does not assert that third-party actions cannot upload.
      if (!job || typeof job !== 'object') {
        reject('invalid job: ' + jobName);
      }
      if (job.steps !== undefined && !Array.isArray(job.steps)) {
        reject('invalid steps: ' + jobName);
      }
      for (const step of job.steps ?? []) {
        if (typeof step?.uses === 'string' &&
            step.uses.toLowerCase().startsWith('actions/upload-artifact')) {
          uploads.push({ workflowName, jobName, step });
        }
      }
    }
  }
  const nativeUploads = uploads.filter(entry =>
    entry.workflowName === 't011-capability-feasibility.yml' &&
    entry.jobName === 'native-probe');
  const portableProducerUploads = uploads.filter(entry =>
    entry.workflowName === 'distribution-candidate.yml' &&
    entry.jobName === 'portable-candidate');
  const portableAcceptanceUploads = uploads.filter(entry =>
    entry.workflowName === 'distribution-candidate.yml' &&
    entry.jobName === 'portable-acceptance');
  const operatorUploads = uploads.filter(entry =>
    entry.workflowName === 'windows-operator-ui-bundle.yml' &&
    entry.jobName === 'native-gui');
  const linuxUiUploads = uploads.filter(entry =>
    entry.workflowName === 'linux-operator-ui-bundle.yml' &&
    entry.jobName === 'native-gui');
  if (uploads.length !== 5 || nativeUploads.length !== 1 ||
      portableProducerUploads.length !== 1 ||
      portableAcceptanceUploads.length !== 1 ||
      operatorUploads.length !== 1 || linuxUiUploads.length !== 1) {
    reject('unreviewed upload action or wrong workflow/job');
  }
  const candidate = portableProducerUploads[0];
  const installer = portableAcceptanceUploads[0];
  if (candidate.step.with?.name !== 'UNPUBLISHED-jdc-portable-' + matrixTarget ||
      installer.step.with?.name !== 'UNPUBLISHED-jdc-installer-' + matrixTarget ||
      candidate.step.uses !== PINNED_UPLOAD || installer.step.uses !== PINNED_UPLOAD ||
      candidate.step.id !== 'portable_tar_upload' ||
      installer.step.id !== 'installer_artifact_upload') {
    reject('candidate/installer upload source identity and pinned actions must match');
  }
  const producer = portable.jobs?.['portable-candidate'];
  const consumer = portable.jobs?.['portable-acceptance'];
  // Never allow a privileged event to feed this read-only, non-release path.
  // On PRs, GitHub supplies a test merge commit; on main pushes, the push SHA.
  const events = portable.on;
  if (!events ||
      JSON.stringify(Object.keys(events).sort()) !== JSON.stringify(['pull_request', 'push']) ||
      JSON.stringify(events.pull_request?.branches) !== JSON.stringify(['main']) ||
      JSON.stringify(events.pull_request?.types) !==
        JSON.stringify(['opened', 'reopened', 'synchronize']) ||
      JSON.stringify(events.push?.branches) !== JSON.stringify(['main'])) {
    reject('portable candidate must run only on unprivileged PRs and main pushes');
  }
  if (Object.keys(portable.permissions ?? {}).length !== 1 ||
      portable.permissions?.contents !== 'read' ||
      producer?.permissions !== undefined || consumer?.permissions !== undefined) {
    reject('portable workflow must retain least permissions');
  }
  if (JSON.stringify(producer?.needs) !==
        JSON.stringify(['windows-operator-ui', 'linux-operator-ui']) ||
      JSON.stringify(consumer?.needs) !==
        JSON.stringify(['portable-candidate', 'windows-operator-ui', 'linux-operator-ui']) ||
      JSON.stringify(producer?.strategy?.matrix) !==
        JSON.stringify(consumer?.strategy?.matrix) ||
      producer?.env?.JDC_CANDIDATE_SOURCE_SHA !== SOURCE_SHA ||
      consumer?.env?.JDC_CANDIDATE_SOURCE_SHA !== SOURCE_SHA ||
      producer?.env?.JDC_CANDIDATE_TARGET !== matrixTarget ||
      consumer?.env?.JDC_CANDIDATE_TARGET !== matrixTarget) {
    reject('producer and acceptance must bind the same immutable platform/source');
  }
  const producerCheckout = producer.steps?.find(step => step.id === 'producer_checkout');
  const consumerCheckout = consumer.steps?.find(step => step.id === 'acceptance_checkout');
  for (const checkout of [producerCheckout, consumerCheckout]) {
    if (checkout?.uses !== PINNED_CHECKOUT ||
        checkout.with?.ref !== SOURCE_SHA ||
        checkout.with?.['persist-credentials'] !== false) {
      reject('producer and acceptance must checkout the same GitHub event SHA');
    }
  }
  const tarHash = producer.steps?.find(step => step.id === 'original_tar_sha256');
  const downloaded = consumer.steps?.find(step => step.id === 'portable_download');
  const beforeDownload = consumer.steps?.find(step => step.id === 'artifact_identity_preflight');
  const roundTrip = consumer.steps?.find(step => step.id === 'portable_roundtrip');
  if (!tarHash?.run?.includes('Get-FileHash') ||
      producer.steps.some(step =>
        String(step?.uses ?? '').startsWith('actions/download-artifact@')) ||
      producer.steps.indexOf(tarHash) >= producer.steps.indexOf(candidate.step) ||
      downloaded?.uses !== PINNED_DOWNLOAD ||
      downloaded?.with?.['artifact-ids'] !== '${{ env.JDC_CANDIDATE_ARTIFACT_ID }}' ||
      downloaded?.with?.['merge-multiple'] !== true ||
      downloaded?.with?.path !== '${{ runner.temp }}/jdc-roundtrip-download/' ||
      downloaded.with.name !== undefined || downloaded.with['github-token'] !== undefined ||
      !beforeDownload?.run?.includes('JDC_CANDIDATE_ORIGINAL_TAR_SHA256') ||
      !beforeDownload?.run?.includes('JDC_CANDIDATE_ARTIFACT_ID') ||
      !roundTrip?.run?.includes('distribution-candidate.mjs roundtrip') ||
      consumer.steps.indexOf(beforeDownload) >= consumer.steps.indexOf(downloaded) ||
      consumer.steps.indexOf(downloaded) >= consumer.steps.indexOf(roundTrip)) {
    reject('cross-job immutable artifact ID, TAR SHA-256 and ordered verification required');
  }
  for (const platform of ['win', 'linux']) {
    const target = platform === 'win' ? 'win32-x64' : 'linux-x64';
    const expectedId = '$' + `{{ matrix.target == '${target}' && steps.portable_tar_upload.outputs.artifact-id || '' }}`;
    const expectedHash = '$' + `{{ matrix.target == '${target}' && steps.original_tar_sha256.outputs.sha256 || '' }}`;
    if (producer.outputs?.[platform + '_artifact_id'] !== expectedId ||
        producer.outputs?.[platform + '_tar_sha256'] !== expectedHash) {
      reject('platform-specific immutable artifact identity and checksum outputs missing');
    }
  }
  const exactPlatformLookup = (suffix) => '$' +
    "{{ fromJSON(format('{{\"win32-x64\":\"{0}\",\"linux-x64\":\"{1}\"}}', needs.portable-candidate.outputs.win_" +
    suffix + ', needs.portable-candidate.outputs.linux_' + suffix + '))[matrix.target] }}';
  const expectedConsumerId = exactPlatformLookup('artifact_id');
  const expectedConsumerHash = exactPlatformLookup('tar_sha256');
  if (consumer.env?.JDC_CANDIDATE_ARTIFACT_ID !== expectedConsumerId ||
      consumer.env?.JDC_CANDIDATE_ORIGINAL_TAR_SHA256 !== expectedConsumerHash) {
    reject('consumer must bind both platform artifact outputs exactly');
  }
  const conf = candidate.step.with;
  if (!conf || conf.name !== 'UNPUBLISHED-jdc-portable-' + matrixTarget ||
      conf.path !== candidatePath ||
      conf['retention-days'] !== 7 ||
      conf['if-no-files-found'] !== 'error' ||
      conf['compression-level'] !== 0) {
    reject('portable upload path or retention differs from reviewed configuration');
  }
  const acceptanceMustPrecedeInstallerUpload = [
    ['portable_roundtrip', /distribution-candidate\.mjs roundtrip/],
    ['packaged_mcp_acceptance', /portable-mcp-e2e\.mjs/],
    ['installer_provenance', /validate-installer-input\.mjs/],
    ['windows_installer_acceptance', /windows-installer-acceptance-runner\.ps1/],
    ['linux_installer_acceptance', /dpkg-deb/],
  ];
  const installerUploadAt = consumer.steps.indexOf(installer.step);
  if (installerUploadAt < 0 || acceptanceMustPrecedeInstallerUpload.some(([id, command]) => {
    const index = consumer.steps.findIndex(step => step.id === id);
    return index < 0 || index >= installerUploadAt ||
      !command.test(consumer.steps[index].run ?? '');
  })) {
    reject('unpublished installers require intact actual MCP and OS acceptance before export');
  }
  const installerConf = installer.step.with;
  if (!installerConf ||
      installerConf.path !== installerPath ||
      installerConf['retention-days'] !== 7 ||
      installerConf['if-no-files-found'] !== 'error' ||
      installerConf['compression-level'] !== 0) {
    reject('installer upload path or retention differs from reviewed configuration');
  }
  validateOperatorUiArtifactPolicy(nativeUi, portable);
  validateLinuxOperatorUiArtifactPolicy(linuxUi, portable);
  return true;
}
