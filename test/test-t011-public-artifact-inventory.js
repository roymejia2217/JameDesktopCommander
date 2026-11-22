import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { parse } from 'yaml';
import { validatePublicArtifactInventory } from './security/support/t011-public-artifact-inventory.js';

const root = path.resolve(import.meta.dirname, '..');
const workflowDir = path.join(root, '.github', 'workflows');
const originals = Object.fromEntries(
  fs.readdirSync(workflowDir)
    .filter((name) => /\.ya?ml$/.test(name))
    .map((name) => [
      name,
      parse(fs.readFileSync(path.join(workflowDir, name), 'utf8'), { uniqueKeys: true }),
    ]),
);
const clone = () => structuredClone(originals);
const findUpload = (job) => job.steps.find((step) =>
  String(step?.uses ?? '').startsWith('actions/upload-artifact@'));
const candidate = (workflows) => workflows['distribution-candidate.yml'].jobs['portable-candidate'];
const acceptance = (workflows) => workflows['distribution-candidate.yml'].jobs['portable-acceptance'];

function mustReject(title, mutate) {
  test(title, () => {
    const docs = clone();
    mutate(docs);
    assert.throws(() => validatePublicArtifactInventory(docs), /E_T011_PUBLIC_ARTIFACT/);
  });
}

test('only the five explicitly reviewed public artifact upload surfaces are allowed', () => {
  assert.equal(validatePublicArtifactInventory(originals), true);
  const all = Object.entries(originals).flatMap(([file, data]) =>
    Object.entries(data.jobs).flatMap(([job, config]) =>
      (config.steps ?? []).filter((step) =>
        String(step?.uses ?? '').startsWith('actions/upload-artifact@'))
        .map(() => file + '/' + job)));
  assert.deepEqual(all.sort(), [
    'distribution-candidate.yml/portable-acceptance',
    'distribution-candidate.yml/portable-candidate',
    'linux-operator-ui-bundle.yml/native-gui',
    't011-capability-feasibility.yml/native-probe',
    'windows-operator-ui-bundle.yml/native-gui',
  ]);
});
test('portable artifact policy uses stable step identities independent of display titles', () => {
  const docs = clone();
  const job = acceptance(docs);
  for (const id of ['acceptance_checkout', 'artifact_identity_preflight',
    'portable_download', 'portable_roundtrip', 'packaged_mcp_acceptance',
    'installer_provenance', 'windows_installer_acceptance',
    'linux_installer_acceptance', 'installer_artifact_upload']) {
    const step = job.steps.find(item => item.id === id);
    assert.ok(step, `Missing expected acceptance control ${id}`);
    step.name = `Display label for ${id}`;
  }
  assert.equal(validatePublicArtifactInventory(docs), true);
});
mustReject('rejects missing stable download identity even with original action and title', docs => {
  const download = acceptance(docs).steps.find(step => step.id === 'portable_download');
  download.id = 'unknown_download';
});
mustReject('rejects new upload in previously nonuploading workflow', (docs) => {
  docs['ci.yml'].jobs['added-proof'] = {
    'runs-on': 'ubuntu-latest',
    steps: [{
      uses: 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
      with: { name: 'token', path: 'native/authority-service/target' },
    }],
  };
});
mustReject('rejects new workflow that exports a native token artifact', (docs) => {
  docs['native-export.yml'] = {
    permissions: { contents: 'read' },
    jobs: { proof: { steps: [{
      uses: 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
      with: { name: 'token', path: 'native/authority-service/target' },
    }] } },
  };
});
mustReject('rejects second upload in portable candidate workflow', (docs) => {
  const job = candidate(docs);
  job.steps.push(structuredClone(findUpload(job)));
});
mustReject('rejects broadening the portable candidate path to runner temp root', (docs) => {
  findUpload(candidate(docs)).with.path = '$' + '{{ runner.temp }}';
});
mustReject('rejects arbitrary SCM path as portable candidate source', (docs) => {
  findUpload(candidate(docs)).with.path = 'native/authority-service/target/**';
});
mustReject('rejects modified portable upload-action SHA', (docs) => {
  findUpload(candidate(docs)).uses = 'actions/upload-artifact@v4';
});
mustReject('rejects changing portable upload identity', (docs) => {
  findUpload(candidate(docs)).with.name = 'SCM-evidence';
});
mustReject('rejects portable artifact retention above reviewed seven days', (docs) => {
  findUpload(candidate(docs)).with['retention-days'] = 8;
});
mustReject('rejects silent portable archive absence', (docs) => {
  findUpload(candidate(docs)).with['if-no-files-found'] = 'warn';
});
mustReject('rejects changed portable artifact compression', (docs) => {
  findUpload(candidate(docs)).with['compression-level'] = 9;
});
mustReject('rejects candidate job-level permission escalation', (docs) => {
  candidate(docs).permissions = { contents: 'write' };
});
mustReject('rejects candidate workflow permission escalation', (docs) => {
  docs['distribution-candidate.yml'].permissions = { contents: 'write' };
});
mustReject('rejects acceptance job actions-token escalation', docs => {
  acceptance(docs).permissions = { contents: 'read', actions: 'read' };
});
mustReject('rejects acceptance that does not depend on completed upload jobs', docs => {
  acceptance(docs).needs = ['windows-operator-ui', 'linux-operator-ui'];
});
mustReject('rejects producer that downloads an unfinalized artifact', docs => {
  candidate(docs).steps.push(structuredClone(acceptance(docs).steps.find(
    step => step.id === 'portable_download')));
});
mustReject('reject producer checkout of attacker-nominated PR head SHA', docs => {
  candidate(docs).steps.find(step => step.name === 'Checkout exact candidate source')
    .with.ref = '${{ github.event.pull_request.head.sha }}';
});
mustReject('reject acceptance checkout from a different source identity', docs => {
  acceptance(docs).steps.find(step => step.name === 'Checkout exact candidate acceptance source')
    .with.ref = 'main';
});
mustReject('reject replacing pull_request with privileged pull_request_target', docs => {
  delete docs['distribution-candidate.yml'].on.pull_request;
  docs['distribution-candidate.yml'].on.pull_request_target = { branches: ['main'] };
});
mustReject('rejects cross-platform artifact ID output confusion', docs => {
  candidate(docs).outputs.win_artifact_id =
    candidate(docs).outputs.linux_artifact_id;
});
mustReject('rejects implicit Linux ID fallback when Windows producer output is absent', docs => {
  acceptance(docs).env.JDC_CANDIDATE_ARTIFACT_ID =
    "${{ matrix.target == 'win32-x64' && needs.portable-candidate.outputs.win_artifact_id || needs.portable-candidate.outputs.linux_artifact_id }}";
});
mustReject('rejects implicit Linux TAR digest fallback when Windows producer output is absent', docs => {
  acceptance(docs).env.JDC_CANDIDATE_ORIGINAL_TAR_SHA256 =
    "${{ matrix.target == 'win32-x64' && needs.portable-candidate.outputs.win_tar_sha256 || needs.portable-candidate.outputs.linux_tar_sha256 }}";
});
mustReject('rejects missing original TAR SHA-256 output', docs => {
  delete candidate(docs).outputs.linux_tar_sha256;
});
mustReject('rejects missing original TAR fingerprint step', docs => {
  candidate(docs).steps = candidate(docs).steps.filter(s =>
    s.id !== 'original_tar_sha256');
});
mustReject('rejects download by mutable name instead of immutable ID', docs => {
  const step = acceptance(docs).steps.find(s =>
    s.id === 'portable_download');
  delete step.with['artifact-ids'];
  step.with.name = 'UNPUBLISHED-jdc-portable-${{ matrix.target }}';
});
mustReject('rejects cross-run token-based artifact download', docs => {
  acceptance(docs).steps.find(s =>
    s.id === 'portable_download')
    .with['github-token'] = '${{ github.token }}';
});
mustReject('rejects bypass of pre-download SHA and identity gate', docs => {
  acceptance(docs).steps = acceptance(docs).steps.filter(s =>
    s.id !== 'artifact_identity_preflight');
});
mustReject('rejects publisher that uploads installer before real host acceptance', docs => {
  const steps = acceptance(docs).steps;
  const at = steps.findIndex(s => s.name === 'Retain unpublished installer candidates');
  const [upload] = steps.splice(at, 1);
  steps.splice(steps.findIndex(s =>
    s.id === 'packaged_mcp_acceptance'), 0, upload);
});
mustReject('rejects producer uploading before recording original SHA-256', docs => {
  const steps = candidate(docs).steps;
  const at = steps.findIndex(s => s.id === 'original_tar_sha256');
  const [hash] = steps.splice(at, 1);
  steps.splice(steps.findIndex(s => s.id === 'portable_tar_upload') + 1, 0, hash);
});
mustReject('rejects removed candidate upload', (docs) => {
  candidate(docs).steps = candidate(docs).steps.filter((s) =>
    !String(s.uses ?? '').startsWith('actions/upload-artifact@'));
});
mustReject('rejects silently missing native evidence workflow', (docs) => {
  delete docs['t011-capability-feasibility.yml'];
});
mustReject('rejects extra native-probe upload even when candidate unaffected', (docs) => {
  const native = docs['t011-capability-feasibility.yml'].jobs['native-probe'];
  native.steps.push(structuredClone(findUpload(native)));
});
mustReject('rejects upload step named without a pinned action ref', (docs) => {
  docs['ci.yml'].jobs['required-ci'].steps.push({ uses: 'actions/upload-artifact', with: {
    name: 'untrusted', path: 'native/authority-service',
  } });
});
const findInstallerUpload = (job) => job.steps.find(step =>
  String(step?.with?.name ?? '').startsWith('UNPUBLISHED-jdc-installer-'));
mustReject('reject installer artifact path broadening to runner temp', docs => {
  findInstallerUpload(acceptance(docs)).with.path = '${{ runner.temp }}';
});
mustReject('reject installer upload with generic wildcard export', docs => {
  findInstallerUpload(acceptance(docs)).with.path =
    '${{ runner.temp }}/jdc-installer-output/*';
});
mustReject('reject changed installer upload target identity', docs => {
  findInstallerUpload(acceptance(docs)).with.name = 'UNPUBLISHED-other';
});
mustReject('reject extended installer retention', docs => {
  findInstallerUpload(acceptance(docs)).with['retention-days'] = 90;
});
mustReject('reject unpinned installer artifact upload action', docs => {
  findInstallerUpload(acceptance(docs)).uses = 'actions/upload-artifact@v4';
});

const operatorUi = docs => docs['windows-operator-ui-bundle.yml'].jobs['native-gui'];
const operatorUpload = docs => findUpload(operatorUi(docs));

mustReject('reject extra upload from the restricted GUI overlay job', docs => {
  operatorUi(docs).steps.push(structuredClone(operatorUpload(docs)));
});
mustReject('reject broad GUI overlay path that could export unrelated files', docs => {
  operatorUpload(docs).with.path = '${{ runner.temp }}/';
});
mustReject('reject changed GUI overlay artifact identity', docs => {
  operatorUpload(docs).with.name = 'UNPUBLISHED-jdc-other';
});
mustReject('reject unpinned GUI overlay upload action', docs => {
  operatorUpload(docs).uses = 'actions/upload-artifact@v4';
});
mustReject('reject GUI artifact retention beyond its reviewed one day', docs => {
  operatorUpload(docs).with['retention-days'] = 7;
});
mustReject('reject GUI job permissions escalated to contents write', docs => {
  docs['windows-operator-ui-bundle.yml'].permissions = { contents: 'write' };
});
mustReject('reject Windows GUI input-controlled source commitment', docs => {
  operatorUi(docs).env.JDC_CANDIDATE_SOURCE_SHA = '${{ inputs.source_commit }}';
});
mustReject('reject Windows GUI caller supplying a mutable source input', docs => {
  docs['distribution-candidate.yml'].jobs['windows-operator-ui'].with = {
    source_commit: '${{ github.event.pull_request.head.sha }}',
  };
});
mustReject('reject GUI build sourcing an unreviewed commit', docs => {
  operatorUi(docs).steps.find(s => s.name === 'Checkout exact native operator source')
    .with.ref = 'main';
});
mustReject('reject GUI artifact upload without prior hash inventory verification', docs => {
  operatorUi(docs).steps.find(s => s.name === 'Build pinned Windows operator UI')
    .run = 'cargo +1.95.0 build --release --locked --manifest-path native/tunnel-operator-ui/Cargo.toml';
});
mustReject('reject portable candidate that drops the same-run GUI dependency', docs => {
  delete docs['distribution-candidate.yml'].jobs['portable-candidate'].needs;
});
mustReject('reject downloaded GUI overlay from an unrelated artifact name', docs => {
  const steps = acceptance(docs).steps;
  const download = steps.find(s => s.name === 'Download exact Windows operator UI overlay');
  download.with.name = 'UNPUBLISHED-untrusted-payload';
});

mustReject('reject GUI build steps that mask failures', docs => {
  operatorUi(docs).steps.find(s => s.name === 'Build pinned Windows operator UI')
    ['continue-on-error'] = true;
});

const linuxOperatorUi = docs => docs['linux-operator-ui-bundle.yml'].jobs['native-gui'];
const linuxOperatorUpload = docs => findUpload(linuxOperatorUi(docs));

mustReject('reject unreviewed Linux GUI overlay path', docs => {
  linuxOperatorUpload(docs).with.path = '${{ runner.temp }}/';
});
mustReject('reject Linux GUI artifact whose identity is not source-bound', docs => {
  linuxOperatorUpload(docs).with.name = 'UNPUBLISHED-jdc-unreviewed';
});
mustReject('reject Linux GUI artifact retention beyond one day', docs => {
  linuxOperatorUpload(docs).with['retention-days'] = 7;
});
mustReject('reject Linux GUI artifact with unpinned upload-action', docs => {
  linuxOperatorUpload(docs).uses = 'actions/upload-artifact@v4';
});
mustReject('reject Linux UI job that silently skips a fork PR', docs => {
  linuxOperatorUi(docs).if = "${{ github.event.pull_request.head.repo.full_name == github.repository }}";
});
mustReject('reject Linux UI input-controlled source commitment', docs => {
  linuxOperatorUi(docs).env.JDC_CANDIDATE_SOURCE_SHA = '${{ inputs.source_commit }}';
});
mustReject('reject unreviewed privileged PR target invocation', docs => {
  docs['distribution-candidate.yml'].on.pull_request_target = { branches: ['main'] };
});
mustReject('reject Linux GUI caller supplying a mutable source input', docs => {
  docs['distribution-candidate.yml'].jobs['linux-operator-ui'].with = {
    source_commit: '${{ github.event.pull_request.head.sha }}',
  };
});
mustReject('reject Linux GUI build from unreviewed source commit', docs => {
  linuxOperatorUi(docs).steps.find(s => s.name === 'Checkout exact native operator source')
    .with.ref = 'main';
});
mustReject('reject Linux GUI build bypassing hashed staging inventory', docs => {
  linuxOperatorUi(docs).steps.find(s =>
    s.name === 'Build pinned Linux operator UI with official Rust toolchain')
    .run = 'cargo +1.95.0 build --release --locked';
});
mustReject('reject Linux GUI build allowing job-level privilege escalation', docs => {
  docs['linux-operator-ui-bundle.yml'].permissions = { contents: 'write' };
});
mustReject('reject unrelated external action in Linux GUI build', docs => {
  linuxOperatorUi(docs).steps.push({
    uses: 'actions/upload-artifact@v4',
    with: { name: 'outside', path: 'native/authority-service/target/' },
  });
});
mustReject('reject Linux GUI candidate without same-run build dependency', docs => {
  acceptance(docs).needs = ['windows-operator-ui'];
});
mustReject('reject Linux GUI downloaded under unapproved artifact name', docs => {
  acceptance(docs).steps.find(s => s.name === 'Download exact Linux operator UI overlay')
    .with.name = 'UNPUBLISHED-wrong-source';
});
mustReject('reject Linux candidate that skips installed hash verification', docs => {
  acceptance(docs).steps.find(s => s.name === 'Verify Debian install and remove')
    .run = 'sudo dpkg -i candidate.deb && sudo dpkg -r jame-desktop-commander';
});
