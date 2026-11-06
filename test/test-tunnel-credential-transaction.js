import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runCredentialRotation } from '../dist/platform/tunnel-credential-transaction.js';

const secretText = 'synthetic-test-token-do-not-log-12345';
const secret = () => new TextEncoder().encode(secretText);
const errorWithSecret = () => new Error('UNTRUSTED ' + secretText + ' C:\\private\\runtime.key');

function fixture({
  fault = null, authority = 'authorized_running', activation = 'activated',
  provider = 'authenticated', restoration = 'restored',
} = {}) {
  const calls = [];
  const port = {
    acquire: async () => {
      calls.push('acquire');
      if (fault === 'acquire') throw errorWithSecret();
      return {
        verifyRegisteredAuthority: async () => {
          calls.push('authority');
          if (fault === 'authority') throw errorWithSecret();
          return authority;
        },
        stage: async bytes => {
          calls.push('stage');
          assert.ok(bytes instanceof Uint8Array);
          assert.equal(new TextDecoder().decode(bytes), secretText);
          if (fault === 'stage') throw errorWithSecret();
        },
        publish: async () => {
          calls.push('publish');
          if (fault === 'publish') throw errorWithSecret();
        },
        activateIfStillAuthorized: async () => {
          calls.push('activate');
          if (fault === 'activate') throw errorWithSecret();
          return activation;
        },
        verifyProviderAuthentication: async () => {
          calls.push('verify');
          if (fault === 'verify') throw errorWithSecret();
          return provider;
        },
        finalize: async () => {
          calls.push('finalize');
          if (fault === 'finalize') throw errorWithSecret();
        },
        restorePriorIfSafe: async () => {
          calls.push('restore');
          if (fault === 'restore') throw errorWithSecret();
          return restoration;
        },
        close: async () => {
          calls.push('close');
          if (fault === 'close') throw errorWithSecret();
        },
      };
    },
  };
  return { port, calls };
}

function sanitized(result, token = secretText) {
  assert.equal(result.kind, 'local_credential_rotation_v1');
  assert.equal(result.remoteRoundTrip, 'not_observed');
  assert.doesNotMatch(JSON.stringify(result), /synthetic-test-token|runtime\.key|private|UNTRUSTED/);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(token));
  assert.ok(!Object.hasOwn(result, 'secret'));
}

test('registered transaction stages, publishes, conditionally activates, verifies and finalizes', async () => {
  const { port, calls } = fixture();
  const bytes = secret();
  const result = await runCredentialRotation(bytes, port);
  assert.deepEqual(result, {
    kind: 'local_credential_rotation_v1',
    state: 'provider_authenticated',
    reasonCode: 'AUTHENTICATED_CONTROL_PLANE',
    remoteRoundTrip: 'not_observed',
  });
  assert.deepEqual(calls, ['acquire', 'authority', 'stage', 'publish',
    'activate', 'verify', 'finalize', 'close']);
  assert.ok(bytes.every(value => value === 0), 'Input ownership must be consumed and zeroed');
  sanitized(result);
});

test('operator STOP blocks all secret staging or service activation', async () => {
  const { port, calls } = fixture({ authority: 'operator_stopped' });
  const bytes = secret();
  const result = await runCredentialRotation(bytes, port);
  assert.equal(result.state, 'denied');
  assert.equal(result.reasonCode, 'OPERATOR_STOPPED');
  assert.deepEqual(calls, ['acquire', 'authority', 'close']);
  assert.ok(bytes.every(value => value === 0));
  sanitized(result);
});

test('ambiguous or invalid authority never stages or activates a service', async () => {
  for (const authority of ['unverified', 'wrong_principal', 'bogus']) {
    const { port, calls } = fixture({ authority });
    const result = await runCredentialRotation(secret(), port);
    assert.equal(result.state, 'denied');
    assert.equal(result.reasonCode, 'AUTHORITY_UNVERIFIED');
    assert.deepEqual(calls, ['acquire', 'authority', 'close']);
    sanitized(result);
  }
});

test('invalid or empty credentials fail before acquiring the OS-backed exclusive lease', async () => {
  for (const bytes of [new Uint8Array(), new Uint8Array([0x41, 0x00, 0x42]),
    new Uint8Array([0x41, 0x0a]), new Uint8Array(8193).fill(0x41)]) {
    const { port, calls } = fixture();
    const result = await runCredentialRotation(bytes, port);
    assert.equal(result.state, 'denied');
    assert.equal(result.reasonCode, 'CREDENTIAL_INPUT_INVALID');
    assert.deepEqual(calls, []);
    assert.ok(bytes.every(value => value === 0));
    sanitized(result);
  }
});

test('denied exclusive lease and exception details never reveal token or path', async () => {
  const { port, calls } = fixture({ fault: 'acquire' });
  const bytes = secret();
  const result = await runCredentialRotation(bytes, port);
  assert.deepEqual(calls, ['acquire']);
  assert.equal(result.state, 'denied');
  assert.equal(result.reasonCode, 'AUTHORITY_UNVERIFIED');
  assert.ok(bytes.every(value => value === 0));
  sanitized(result);
});

test('staging or publication failures require safe cleanup; no activation', async () => {
  for (const fault of ['stage', 'publish']) {
    const { port, calls } = fixture({ fault });
    const result = await runCredentialRotation(secret(), port);
    assert.equal(result.state, 'prior_credential_restored_unverified');
    assert.equal(result.reasonCode, 'STAGING_OR_PUBLICATION_REVERTED');
    assert.deepEqual(calls, fault === 'stage'
      ? ['acquire', 'authority', 'stage', 'restore', 'close']
      : ['acquire', 'authority', 'stage', 'publish', 'restore', 'close']);
    sanitized(result);
  }
});

test('provider 401 rejection or inconclusive health rolls back, not success', async () => {
  const cases = {
    rejected_401: 'CONTROL_PLANE_401_REVERTED',
    forbidden_403: 'CONTROL_PLANE_403_REVERTED',
    rate_limited_429: 'CONTROL_PLANE_429_REVERTED',
    unverified: 'AUTHENTICATION_UNVERIFIED_REVERTED',
    wrong_status: 'AUTHENTICATION_UNVERIFIED_REVERTED',
  };
  for (const [provider, reason] of Object.entries(cases)) {
    const { port, calls } = fixture({ provider });
    const result = await runCredentialRotation(secret(), port);
    assert.equal(result.state, 'prior_credential_restored_unverified');
    assert.equal(result.reasonCode, reason);
    assert.deepEqual(calls, ['acquire', 'authority', 'stage', 'publish',
      'activate', 'verify', 'restore', 'close']);
    sanitized(result);
  }
});

test('STOP occurring during conditional activation does not trigger a second start', async () => {
  const { port, calls } = fixture({ activation: 'operator_stopped' });
  const result = await runCredentialRotation(secret(), port);
  assert.equal(result.state, 'prior_credential_restored_unverified');
  assert.equal(result.reasonCode, 'OPERATOR_STOPPED_DURING_HANDOVER');
  assert.deepEqual(calls, ['acquire', 'authority', 'stage', 'publish',
    'activate', 'restore', 'close']);
  assert.ok(!calls.includes('verify'));
  sanitized(result);
});

test('rollback failure is never reported as restored, authenticated or healthy', async () => {
  const { port, calls } = fixture({ fault: 'restore', provider: 'rejected_401' });
  const result = await runCredentialRotation(secret(), port);
  assert.equal(result.state, 'recovery_required');
  assert.equal(result.reasonCode, 'RESTORATION_UNCERTAIN');
  assert.ok(calls.includes('restore'));
  assert.ok(calls.includes('close'));
  sanitized(result);
});

test('finalization errors leave a durable recovery requirement, never silently succeed', async () => {
  const { port, calls } = fixture({ fault: 'finalize' });
  const result = await runCredentialRotation(secret(), port);
  assert.equal(result.state, 'recovery_required');
  assert.equal(result.reasonCode, 'FINALIZATION_UNCERTAIN');
  assert.ok(!calls.includes('restore'), 'Cannot revert an authenticated key during uncertain finalize');
  assert.deepEqual(calls.at(-1), 'close');
  sanitized(result);
});

test('release of OS lease must not be hidden if it fails', async () => {
  const { port, calls } = fixture({ fault: 'close' });
  const result = await runCredentialRotation(secret(), port);
  assert.equal(result.state, 'recovery_required');
  assert.equal(result.reasonCode, 'LEASE_RELEASE_UNCERTAIN');
  assert.deepEqual(calls.at(-1), 'close');
  sanitized(result);
});

test('unexpected activation result fails closed and never verifies or finalizes', async () => {
  const { port, calls } = fixture({ activation: 'unexpected' });
  const result = await runCredentialRotation(secret(), port);
  assert.equal(result.state, 'prior_credential_restored_unverified');
  assert.equal(result.reasonCode, 'ACTIVATION_DENIED_REVERTED');
  assert.ok(!calls.includes('verify'));
  assert.ok(!calls.includes('finalize'));
  sanitized(result);
});

test('secret is cleared before acquiring a lease and right after stage returns', async () => {
  const bytes = secret();
  const { port, calls } = fixture();
  const originalAcquire = port.acquire;
  port.acquire = async () => {
    assert.ok(bytes.every(value => value === 0), 'Caller input must not survive await boundary');
    const session = await originalAcquire();
    let borrowed;
    const originalStage = session.stage;
    session.stage = async secretBytes => {
      borrowed = secretBytes;
      await originalStage(secretBytes);
    };
    const originalPublish = session.publish;
    session.publish = async () => {
      assert.ok(borrowed.every(value => value === 0),
        'The staging view must be cleared before publication or network activity');
      return originalPublish();
    };
    return session;
  };
  const result = await runCredentialRotation(bytes, port);
  assert.equal(result.state, 'provider_authenticated');
  assert.ok(calls.includes('stage'));
  sanitized(result);
});

test('restoration pending and unexpected restore result cannot claim safe recovery', async () => {
  for (const restoration of ['pending', 'unrecognized']) {
    const { port, calls } = fixture({ restoration, provider: 'rejected_401' });
    const result = await runCredentialRotation(secret(), port);
    assert.equal(result.state, 'recovery_required');
    assert.equal(result.reasonCode, 'RESTORATION_UNCERTAIN');
    assert.ok(calls.includes('restore'));
    sanitized(result);
  }
});

test('exceptions in preflight and activation deny or roll back without secret leakage', async () => {
  const before = fixture({ fault: 'authority' });
  const denied = await runCredentialRotation(secret(), before.port);
  assert.equal(denied.state, 'denied');
  assert.deepEqual(before.calls, ['acquire', 'authority', 'close']);
  sanitized(denied);

  const after = fixture({ fault: 'activate' });
  const reverted = await runCredentialRotation(secret(), after.port);
  assert.equal(reverted.state, 'prior_credential_restored_unverified');
  assert.equal(reverted.reasonCode, 'ACTIVATION_DENIED_REVERTED');
  assert.deepEqual(after.calls, ['acquire', 'authority', 'stage',
    'publish', 'activate', 'restore', 'close']);
  sanitized(reverted);
});

test('reject all ASCII control bytes and DEL in protected paste-once input', async () => {
  for (const code of [1, 9, 27, 31, 127]) {
    const bytes = new Uint8Array([65, code, 66]);
    const { port, calls } = fixture();
    const result = await runCredentialRotation(bytes, port);
    assert.equal(result.reasonCode, 'CREDENTIAL_INPUT_INVALID');
    assert.deepEqual(calls, []);
    assert.ok(bytes.every(value => value === 0));
    sanitized(result);
  }
});
