// OC-07.2e: fail-closed, test-only guard for the existing public native artifact.
const ALLOWED = new Set([
  'native/capability-probe/Cargo.lock',
  'native/capability-probe/target/release/jdc-capability-probe.node',
]);

function reject(reason) {
  throw new Error('E_T011_ARTIFACT_POLICY: ' + reason);
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
  if (!jobs || Object.keys(jobs).length !== 1 || !jobs['native-probe']) {
    reject('unexpected workflow job');
  }
  const job = jobs['native-probe'];
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
