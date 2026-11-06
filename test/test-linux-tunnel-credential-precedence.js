import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  inspectLinuxManagerRuntimeKeyEnvironment,
} from '../dist/platform/linux/tunnel-lifecycle.js';

test('manager key override is denied even if a profile references a file', () => {
  for (const raw of [
    'CONTROL_PLANE_API_KEY=synthetic-not-a-real-token\n',
    'OPENAI_API_KEY=synthetic-not-a-real-token\n',
    'LANG=C\nCONTROL_PLANE_API_KEY=\nHOME=/home/fixture\n',
    'PATH=/usr/bin\nOPENAI_API_KEY=untrusted\n',
  ]) {
    const result = inspectLinuxManagerRuntimeKeyEnvironment(raw);
    assert.equal(result, 'override_present');
    assert.doesNotMatch(result, /synthetic|OPENAI_API_KEY|CONTROL_PLANE_API_KEY/);
  }
});

test('unrelated systemd environment cannot authorize or masquerade as API key override', () => {
  for (const raw of [
    '', 'LANG=C\nHOME=/home/fixture\n',
    'NOT_CONTROL_PLANE_API_KEY=synthetic-only\n',
    'X_OPENAI_API_KEY=synthetic-only\n',
  ]) {
    assert.equal(inspectLinuxManagerRuntimeKeyEnvironment(raw), 'no_override_observed');
  }
});

test('malformed or excessive manager environment evidence fails closed without echoing values', () => {
  for (const raw of [
    'NOT_AN_ASSIGNMENT\n',
    'LANG=C\nMALFORMED SECRET\n',
    'HOME=/home/fixture\u0000junk\n',
    42, null, undefined, 'A='.padEnd(65_538, 'x'),
  ]) {
    const result = inspectLinuxManagerRuntimeKeyEnvironment(raw);
    assert.equal(result, 'unverified');
    assert.doesNotMatch(result, /MALFORMED|home|SECRET/);
  }
});
