import path from 'node:path';

const explicitConfigDir = process.env.DESKTOP_COMMANDER_CONFIG_DIR?.trim();

if (!explicitConfigDir) {
  const baseRoot =
    process.env.DESKTOP_COMMANDER_TEST_CONFIG_ROOT?.trim()
    || path.resolve('.tmp', 'test-config');

  process.env.DESKTOP_COMMANDER_CONFIG_DIR = path.resolve(
    baseRoot,
    String(process.pid),
  );
}
