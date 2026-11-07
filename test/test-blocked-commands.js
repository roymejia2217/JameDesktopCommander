import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { configManager } from '../dist/config-manager.js';
import { commandManager } from '../dist/command-manager.js';

let originalBlockedCommands;

before(async () => {
  const { blockedCommands } = await configManager.getConfig();
  assert.ok(Array.isArray(blockedCommands), 'isolated test config needs a blocklist');
  originalBlockedCommands = [...blockedCommands];
});

after(async () => {
  try {
    if (originalBlockedCommands !== undefined) {
      await configManager.setValue('blockedCommands', originalBlockedCommands);
    }
  } finally {
    await configManager.close();
  }
});

test('blockedCommands rejects destructive tokens without executing them', async () => {
  const blocked = ['rm', 'mkfs', 'dd'];
  await configManager.setValue('blockedCommands', blocked);
  assert.deepEqual((await configManager.getConfig()).blockedCommands, blocked);

  for (const command of blocked) {
    assert.equal(await commandManager.validateCommand(command), false, command);
  }
  assert.equal(await commandManager.validateCommand('echo harmless && rm -rf /'), false);
});

test('blockedCommands permits unblocked harmless commands', async () => {
  await configManager.setValue('blockedCommands', ['rm', 'mkfs', 'dd']);
  for (const command of ['echo "Hello World"', 'pwd', 'date']) {
    assert.equal(await commandManager.validateCommand(command), true, command);
  }
});

test('blockedCommands changes apply immediately', async () => {
  await configManager.setValue('blockedCommands', ['echo']);
  assert.equal(await commandManager.validateCommand('echo safe'), false);
  await configManager.setValue('blockedCommands', []);
  assert.equal(await commandManager.validateCommand('echo safe'), true);
});

test('empty blockedCommands clears validation denials without process execution', async () => {
  await configManager.setValue('blockedCommands', []);
  assert.deepEqual((await configManager.getConfig()).blockedCommands, []);
  // This exercises validation only. No shell/process call is permitted here.
  for (const command of ['rm', 'mkfs', 'dd']) {
    assert.equal(await commandManager.validateCommand(command), true, command);
  }
});
