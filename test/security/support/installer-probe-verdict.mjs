import assert from 'node:assert/strict';

// Never mistake failure to execute a security probe for a successful denial.
// Only fixed diagnostic codes are emitted; subprocess paths and output may
// contain private data and must not be included in infrastructure errors.
const errorCodes = new Set(['ETIMEDOUT', 'ENOENT', 'EACCES', 'EPERM', 'ENOBUFS',
  'EINVAL', 'EAGAIN', 'ENOMEM', 'EMFILE', 'ENFILE']);

export function assertInstallerProbeExit(result, expectedStatus) {
  assert.ok(expectedStatus === 0 || expectedStatus === 1, 'E_INSTALLER_PROBE_EXPECTATION');
  if (result.error) {
    const code = errorCodes.has(result.error.code) ? result.error.code : 'UNKNOWN';
    assert.fail('E_INSTALLER_PROBE_SPAWN_' + code);
  }
  assert.ok(result.signal === null, 'E_INSTALLER_PROBE_SIGNAL');
  assert.ok(Number.isInteger(result.status), 'E_INSTALLER_PROBE_NO_EXIT_STATUS');
  assert.equal(result.status, expectedStatus, 'E_INSTALLER_PROBE_EXIT_STATUS');
}
