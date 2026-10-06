import path from 'path';
import os from 'os';
import { parseArgs } from 'node:util';

export function resolveConfigDirectory(
  args: string[] = process.argv.slice(2),
  homeDirectory = os.homedir(),
  environment: NodeJS.ProcessEnv = process.env,
): string {
  const { values } = parseArgs({
    args,
    options: {
      'config-dir': { type: 'string' },
    },
    strict: false,
    allowPositionals: true,
  });

  const cliDirectory = values['config-dir'];
  if (typeof cliDirectory === 'string' && cliDirectory.trim().length > 0) {
    return path.resolve(cliDirectory);
  }

  const environmentDirectory = environment.DESKTOP_COMMANDER_CONFIG_DIR?.trim();
  if (environmentDirectory) {
    return path.resolve(environmentDirectory);
  }

  return path.join(homeDirectory, '.claude-server-commander');
}

export const USER_HOME = os.homedir();
export const CONFIG_DIR = resolveConfigDirectory();
export const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
export const TOOL_CALL_FILE = path.join(CONFIG_DIR, 'claude_tool_call.log');
export const TOOL_CALL_FILE_MAX_SIZE = 1024 * 1024 * 10;

export const DEFAULT_COMMAND_TIMEOUT = 1000;
