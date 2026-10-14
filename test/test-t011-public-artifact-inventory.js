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

function mustReject(title, mutate) {
  test(title, () => {
    const docs = clone();
    mutate(docs);
    assert.throws(() => validatePublicArtifactInventory(docs), /E_T011_PUBLIC_ARTIFACT/);
  });
}

test('only the two reviewed public artifact upload surfaces are allowed', () => {
  assert.equal(validatePublicArtifactInventory(originals), true);
  const all = Object.entries(originals).flatMap(([file, data]) =>
    Object.entries(data.jobs).flatMap(([job, config]) =>
      (config.steps ?? []).filter((step) =>
        String(step?.uses ?? '').startsWith('actions/upload-artifact@'))
        .map(() => file + '/' + job)));
  assert.deepEqual(all.sort(), [
    'distribution-candidate.yml/portable-candidate',
    't011-capability-feasibility.yml/native-probe',
  ]);
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
