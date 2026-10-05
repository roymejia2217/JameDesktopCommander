#!/usr/bin/env node

/**
 * Verify ripgrep binary availability using the same resolver as production.
 *
 * @vscode/ripgrep 1.18+ ships platform binaries through optionalDependencies,
 * so verification must work even when npm lifecycle scripts are disabled.
 */

import { getRipgrepPath } from '../utils/ripgrep-resolver.js';

async function verifyRipgrep() {
  try {
    const path = await getRipgrepPath();
    console.log(`✓ ripgrep found at: ${path}`);
    process.exit(0);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('⚠ Warning: ripgrep binary not available');
    console.error(`${message}`);
    console.error('');
    console.error('Desktop Commander will not work until ripgrep is available.');
    console.error('The bundled @vscode/ripgrep platform package or a supported system fallback is missing.');
    console.error('');
    console.error('Reinstall the locked dependencies first. If a system fallback is intentional:');
    console.error('  macOS: brew install ripgrep');
    console.error('  Linux: See https://github.com/BurntSushi/ripgrep#installation');
    console.error('  Windows: winget install BurntSushi.ripgrep.MSVC');
    process.exit(1);
  }
}

verifyRipgrep();
