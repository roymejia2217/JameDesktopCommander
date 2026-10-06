import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function stringEnvironment(baseEnv) {
  return Object.fromEntries(
    Object.entries(baseEnv).filter(([, value]) => typeof value === 'string'),
  );
}

export function createIsolatedHomeEnvironment(
  prefix = 'dc-isolated-home-',
  baseEnv = process.env,
) {
  const home = mkdtempSync(path.join(os.tmpdir(), prefix));
  let cleaned = false;

  return {
    home,
    env: {
      ...stringEnvironment(baseEnv),
      HOME: home,
      USERPROFILE: home,
    },
    cleanup() {
      if (cleaned) return;
      cleaned = true;
      rmSync(home, { recursive: true, force: true });
    },
  };
}
