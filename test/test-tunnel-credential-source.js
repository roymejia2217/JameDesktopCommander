import assert from 'node:assert/strict';
import { test } from 'node:test';
import { classifyTunnelCredentialSource } from '../dist/platform/tunnel-credential-source.js';

test('supported provider secret references are recognized without disclosing paths', () => {
  for (const key of ['file:/home/operator/runtime.key',
    'file:C:\\Secrets\\runtime.key', 'file:/var/lib/private/runtime.key']) {
    const result = classifyTunnelCredentialSource({ control_plane: { api_key: key } });
    assert.equal(result, 'file_reference');
    assert.doesNotMatch(JSON.stringify({ credentialSource: result }), /runtime\.key|Secrets/);
  }
  assert.equal(classifyTunnelCredentialSource({
    control_plane: { api_key: 'env:CONTROL_PLANE_API_KEY' },
  }), 'environment_reference');
});

test('missing source cannot become a supported secret source', () => {
  for (const value of [null, {}, { control_plane: {} },
    { control_plane: null }, { control_plane: [] }, { control_plane: { api_key: null } }]) {
    assert.equal(classifyTunnelCredentialSource(value), 'unverified');
  }
});
test('rejects literals, remote references and malformed source syntax', () => {
  for (const source of ['sk-secret-do-not-log', 'file:relative.key',
    'file:../private.key', 'file://remote.example/key',
    'file:\\\\server\\share\\key', 'env:BAD-NAME',
    'env:API KEY', 'env:', 'file:', 'file:/']) {
    const result = classifyTunnelCredentialSource({
      control_plane: { api_key: source },
    });
    assert.equal(result, 'unsupported', source.startsWith('sk-') ? 'literal' : source);
    assert.doesNotMatch(JSON.stringify({ credentialSource: result }),
      /secret-do-not-log|remote\.example|private\.key|server/i);
  }
});

test('malformed reference never evaluates user data or returns arbitrary payload', () => {
  let coercions = 0;
  const hostile = { toString() { coercions++; throw Error('LEAKED_SECRET'); } };
  assert.equal(classifyTunnelCredentialSource({
    control_plane: { api_key: hostile },
  }), 'unsupported');
  assert.equal(coercions, 0);
});
