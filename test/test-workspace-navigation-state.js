import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createWidgetStateStorage } from '../dist/ui/shared/widget-state.js';
import {
  WORKSPACE_STATE_VERSION,
  createWorkspaceState,
  isPersistedWorkspaceState,
  normalizeWorkspaceState,
} from '../dist/ui/file-preview/src/workspace-state.js';

const directory = {
  fileName: 'test',
  filePath: 'E:\\repo\\test',
  fileType: 'directory',
  sourceTool: 'render_workspace',
  content: '[FILE] sample.js',
};

const file = {
  fileName: 'sample.js',
  filePath: 'E:\\repo\\test\\sample.js',
  fileType: 'text',
  sourceTool: 'read_file',
  content: 'console.log("ok");',
};

const navigated = createWorkspaceState(directory.filePath, file, directory);
assert.equal(navigated.version, WORKSPACE_STATE_VERSION);
assert.equal(navigated.rootPath, directory.filePath);
assert.deepEqual(navigated.currentPayload, file);
assert.deepEqual(navigated.directoryBackPayload, directory);
assert.equal(isPersistedWorkspaceState(navigated), true);
assert.deepEqual(normalizeWorkspaceState(navigated), navigated);

const returnedToDirectory = createWorkspaceState(directory.filePath, directory, file);
assert.equal(
  returnedToDirectory.directoryBackPayload,
  undefined,
  'directory view must not retain a stale Back payload',
);

const legacy = normalizeWorkspaceState(directory);
assert.equal(legacy?.rootPath, directory.filePath);
assert.deepEqual(legacy?.currentPayload, directory);
assert.equal(legacy?.directoryBackPayload, undefined);
assert.equal(isPersistedWorkspaceState({ version: 1, rootPath: directory.filePath }), false);
assert.equal(
  isPersistedWorkspaceState({ ...navigated, directoryBackPayload: file }),
  false,
  'Back payload must be a directory',
);
assert.equal(
  isPersistedWorkspaceState({ ...navigated, directoryBackPayload: { ...directory, filePath: 'E:\\repo\\other' } }),
  false,
  'Back payload must match the workspace root',
);
assert.throws(
  () => createWorkspaceState(directory.filePath, file, { ...directory, filePath: 'E:\\repo\\other' }),
  /root directory/,
  'state construction must fail closed on a mismatched Back directory',
);

const originalWindow = globalThis.window;
let chatGptState;
try {
  globalThis.window = {
    openai: {
      get widgetState() {
        return chatGptState;
      },
      setWidgetState(nextState) {
        chatGptState = nextState;
      },
    },
  };
  const storage = createWidgetStateStorage(isPersistedWorkspaceState);
  storage.write(createWorkspaceState(directory.filePath, directory));
  storage.write(navigated);

  const restored = normalizeWorkspaceState(storage.read());
  assert.deepEqual(restored?.currentPayload, file, 'rehydration must keep the selected child file');
  assert.deepEqual(restored?.directoryBackPayload, directory, 'rehydration must preserve Back to the directory');
  assert.equal(restored?.rootPath, directory.filePath, 'rehydration must retain the workspace root path');

  storage.write(createWorkspaceState(directory.filePath, directory));
  const restoredAfterBack = normalizeWorkspaceState(storage.read());
  assert.deepEqual(restoredAfterBack?.currentPayload, directory, 'Back must persist the directory as the current view');
  assert.equal(restoredAfterBack?.directoryBackPayload, undefined, 'Back must clear the stale child navigation state');
} finally {
  globalThis.window = originalWindow;
}

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const appSource = await fs.readFile(
  path.resolve(testDirectory, '..', 'src', 'ui', 'file-preview', 'src', 'app.ts'),
  'utf8',
);

assert.match(
  appSource,
  /onOpenPayload:\s*\(nextPayload\)\s*=>\s*\{[^}]*directoryBackPayload = payload;[^}]*persistPayload\?\.\(nextPayload\);[^}]*renderApp\(container, nextPayload, 'rendered', true\);/s,
  'directory → file navigation must persist the visible file before rendering it',
);

assert.match(
  appSource,
  /backBtn\.addEventListener\('click', \(\) => \{[^}]*directoryBackPayload = undefined;[^}]*persistPayload\?\.\(savedPayload\);[^}]*renderApp\(container, savedPayload, 'rendered', true\);/s,
  'Back navigation must persist the directory payload before rendering it',
);

assert.match(
  appSource,
  /syncFromPersistedWidgetState[\s\S]*?readWorkspaceState\(\)[\s\S]*?restoreWorkspaceState\(persistedState\)/,
  'visibility restoration must restore the full workspace snapshot',
);
assert.match(
  appSource,
  /pendingCachedState\.rootPath === requestedPath[\s\S]*?resolveInitialState\(restoreWorkspaceState\(cached\)\)/,
  'remount hydration must match the original root and restore internal navigation',
);
assert.match(
  appSource,
  /const cached = pendingCachedState;[\s\S]*?renderedForCurrentInput = true;[\s\S]*?resolveInitialState\(restoreWorkspaceState\(cached\)\)/,
  'cached remount hydration must suppress the late root tool-result',
);

console.log('Workspace navigation persistence contract: PASS');
