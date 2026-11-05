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

/** Restrict the known official upload-artifact action throughout all workflows. */
export function validatePublicArtifactInventory(workflows) {
  if (!workflows || typeof workflows !== 'object' || Array.isArray(workflows)) {
    reject('expected parsed workflow mapping');
  }
  const native = workflows['t011-capability-feasibility.yml'];
  const portable = workflows['distribution-candidate.yml'];
  if (!native || !portable) {
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
  const portableUploads = uploads.filter(entry =>
    entry.workflowName === 'distribution-candidate.yml' &&
    entry.jobName === 'portable-candidate');
  if (uploads.length !== 3 || nativeUploads.length !== 1 ||
      portableUploads.length !== 2) {
    reject('unreviewed upload action or wrong workflow/job');
  }
  const candidate = portableUploads.find(entry =>
    entry.step.with?.name === 'UNPUBLISHED-jdc-portable-' + matrixTarget);
  const installer = portableUploads.find(entry =>
    entry.step.with?.name === 'UNPUBLISHED-jdc-installer-' + matrixTarget);
  if (!candidate || !installer || installer.step.uses !== PINNED_UPLOAD) {
    reject('installer upload identity or pinned action mismatch');
  }
  if (candidate.step.uses !== PINNED_UPLOAD) {
    reject('portable upload action SHA not pinned');
  }
  if (Object.keys(portable.permissions ?? {}).length !== 1 ||
      portable.permissions?.contents !== 'read' ||
      portable.jobs['portable-candidate']?.permissions !== undefined) {
    reject('portable workflow must retain least permissions');
  }
  const conf = candidate.step.with;
  if (!conf || conf.name !== 'UNPUBLISHED-jdc-portable-' + matrixTarget ||
      conf.path !== candidatePath ||
      conf['retention-days'] !== 7 ||
      conf['if-no-files-found'] !== 'error' ||
      conf['compression-level'] !== 0) {
    reject('portable upload path or retention differs from reviewed configuration');
  }
  const installerConf = installer.step.with;
  if (!installerConf ||
      installerConf.path !== installerPath ||
      installerConf['retention-days'] !== 7 ||
      installerConf['if-no-files-found'] !== 'error' ||
      installerConf['compression-level'] !== 0) {
    reject('installer upload path or retention differs from reviewed configuration');
  }
  return true;
}
