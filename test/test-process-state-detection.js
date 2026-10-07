#!/usr/bin/env node

import assert from 'node:assert/strict';
import test from 'node:test';

import { analyzeProcessState } from '../dist/utils/process-detection.js';

test('git percentage progress is not treated as an interactive prompt', () => {
  const state = analyzeProcessState('Updating files:  42% (166/394)\r');
  assert.equal(state.isWaitingForInput, false);
  assert.equal(state.detectedPrompt, undefined);
});

test('a real percent shell prompt remains interactive', () => {
  const state = analyzeProcessState('% ');
  assert.equal(state.isWaitingForInput, true);
  assert.equal(state.detectedPrompt, '% ');
});

test('a named REPL prompt remains interactive', () => {
  const state = analyzeProcessState('mysql> ');
  assert.equal(state.isWaitingForInput, true);
  assert.equal(state.detectedPrompt, 'mysql> ');
});
