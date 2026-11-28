import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { parse } from 'yaml';
import { validateNativeArtifactPolicy } from './security/support/t011-native-artifact-policy.js';

const root = path.resolve(import.meta.dirname, '..');
const filename = path.join(root, '.github/workflows/t011-capability-feasibility.yml');
const source = fs.readFileSync(filename, 'utf8');
const workflow = parse(source, { uniqueKeys: true });
const expectedPaths = [
  'native/capability-probe/Cargo.lock',
  'native/capability-probe/target/release/jdc-capability-probe.node',
];
const upload = (job) => job.steps.find((step) => String(step.uses ?? '').startsWith('actions/upload-artifact@'));
const clone = () => structuredClone(workflow);

function rejectChange(description, change) {
  test(description, () => {
    const candidate = clone();
    change(candidate.jobs['native-probe'], candidate);
    assert.throws(() => validateNativeArtifactPolicy(candidate), /E_T011_ARTIFACT_POLICY/);
  });
}

test('native capability workflow has an explicit fixed allowlist for unpublished artifacts', () => {
  assert.equal(validateNativeArtifactPolicy(workflow), true);
  const paths = upload(workflow.jobs['native-probe']).with.path.trim().split(/\r?\n/).map((s) => s.trim());
  assert.deepEqual(paths, expectedPaths);
});

rejectChange('rejects publishing authority-service target outputs', (job) => {
  upload(job).with.path += '\n  native/authority-service/target/**';
});
rejectChange('rejects broad native directory globs', (job) => {
  upload(job).with.path = 'native/**';
});
rejectChange('rejects any GitHub expression in uploaded paths', (job) => {
  upload(job).with.path = '$' + '{{ github.workspace }}/native/capability-probe/Cargo.lock';
});
rejectChange('rejects globbed binary names in place of exact paths', (job) => {
  upload(job).with.path = 'native/capability-probe/target/release/*.node';
});
rejectChange('rejects duplicate artifact upload steps', (job) => {
  job.steps.push(structuredClone(upload(job)));
});
rejectChange('rejects removal of mandated upload', (job) => {
  job.steps = job.steps.filter((step) => !String(step.uses ?? '').startsWith('actions/upload-artifact@'));
});
rejectChange('rejects unpinned upload-artifact action', (job) => {
  upload(job).uses = 'actions/upload-artifact@v4';
});
rejectChange('rejects retention over one day', (job) => {
  upload(job).with['retention-days'] = 30;
});
rejectChange('rejects silent artifact absence', (job) => {
  upload(job).with['if-no-files-found'] = 'warn';
});
rejectChange('rejects missing workflow permission confinement', (_job, doc) => {
  doc.permissions = { contents: 'write' };
});
rejectChange('rejects altered pinned upload revision', (job) => {
  upload(job).uses = 'actions/upload-artifact@0123456789012345678901234567890123456789';
});
rejectChange('rejects extra native probe jobs', (_job, doc) => {
  doc.jobs.unreviewed = { 'runs-on': 'windows-latest', steps: [] };
});
test('SCM storage research runs in a separate mandatory artifact-free job', () => {
  const isolated = workflow.jobs['scm-storage-nonrelease'];
  assert.ok(isolated, 'missing isolated SCM storage job');
  assert.equal(isolated['runs-on'], 'windows-2025');
  assert.equal(isolated.if, undefined);
  assert.equal(isolated['continue-on-error'], undefined);
  assert.equal(isolated.needs, undefined);
  assert.equal(isolated.outputs, undefined);
  assert.equal(isolated.permissions, undefined);
  assert.equal(isolated.steps.filter(s => s.id === 'windows_scm_admitted_storage').length, 1);
  assert.ok(isolated.steps.every(s => !/upload-artifact|download-artifact|actions\/cache/i.test(s.uses ?? '')));
  assert.ok(workflow.jobs['native-probe'].steps.every(s => !/--features|scm-storage-proof/.test(s.run ?? '')));
});
rejectChange('rejects removal of isolated SCM storage acceptance', (_job, doc) => {
  delete doc.jobs['scm-storage-nonrelease'];
});
rejectChange('rejects isolated SCM job permission escalation', (_job, doc) => {
  doc.jobs['scm-storage-nonrelease'].permissions = { contents: 'write' };
});
rejectChange('rejects publication from isolated SCM storage', (_job, doc) => {
  doc.jobs['scm-storage-nonrelease'].steps.push(structuredClone(upload(doc.jobs['native-probe'])));
});
rejectChange('rejects optional isolated SCM acceptance', (_job, doc) => {
  doc.jobs['scm-storage-nonrelease']['continue-on-error'] = true;
});
rejectChange('rejects disabling the isolated acceptance step', (_job, doc) => {
  doc.jobs['scm-storage-nonrelease'].steps.find(s => s.id === 'windows_scm_admitted_storage').if = false;
});
rejectChange('rejects isolated SCM job output handoff', (_job, doc) => {
  doc.jobs['scm-storage-nonrelease'].outputs = { unreviewed: 'value' };
});
rejectChange('rejects isolated SCM acceptance with a forced successful exit', (_job, doc) => {
  const step = doc.jobs['scm-storage-nonrelease'].steps.find(s => s.id === 'windows_scm_admitted_storage');
  step.run = 'exit 0\n' + step.run;
});
rejectChange('rejects isolated research build with a forced successful exit', (_job, doc) => {
  const step = doc.jobs['scm-storage-nonrelease'].steps.find(s => s.id === 'scm_storage_native');
  step.run = 'exit 0\n' + step.run;
});
rejectChange('rejects isolated job on a persistent self-hosted runner', (_job, doc) => {
  doc.jobs['scm-storage-nonrelease']['runs-on'] = 'self-hosted';
});
rejectChange('rejects isolated runtime automatic package cache', (_job, doc) => {
  doc.jobs['scm-storage-nonrelease'].steps.find(s => s.id === 'scm_storage_node').with['package-manager-cache'] = true;
});
rejectChange('rejects artifact producer dependency on experimental job', (job) => {
  job.needs = ['scm-storage-nonrelease'];
});
rejectChange('rejects native job permission overrides', (job) => {
  job.permissions = { contents: 'write' };
});
rejectChange('rejects duplicate approved artifact paths', (job) => {
  upload(job).with.path = 'native/capability-probe/Cargo.lock\nnative/capability-probe/Cargo.lock';
});
rejectChange('rejects altered artifact naming', (job) => {
  upload(job).with.name = 'evidence-' + '$' + '{{ matrix.target }}';
});
rejectChange('rejects altered compression policy', (job) => {
  upload(job).with['compression-level'] = 9;
});
