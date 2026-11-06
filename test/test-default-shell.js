/**
 * Test script for defaultShell configuration functionality
 * 
 * This script tests how defaultShell settings affect command execution:
 * 1. Testing execution with /bin/sh as default shell
 * 2. Testing execution with bash as default shell
 * 3. Testing shell changes are properly applied
 * 4. Testing restoration of original configuration
 */

import { configManager } from '../dist/config-manager.js';
import { startProcess, readProcessOutput, forceTerminate } from '../dist/tools/improved-process-tools.js';
import assert from 'assert';
import os from 'os';
import path from 'node:path';
import { after, before, test } from 'node:test';

// We need a wrapper because startProcess in tools/improved-process-tools.js returns a ServerResult
// but our tests expect to receive the actual command result
async function executeCommand(command, timeout_ms = 2000, shell = null) {
  const args = {
    command: command,
    timeout_ms: timeout_ms
  };
  
  if (shell) {
    args.shell = shell;
  }
  
  return await startProcess(args);
}

async function runCommandToExit(command, initialTimeoutMs = 2000, shell = null) {
  const started = await executeCommand(command, initialTimeoutMs, shell);
  const initial = started.content?.[0]?.text ?? '';
  assert.notEqual(started.isError, true, initial);
  const match = initial.match(/Process started with PID (\d+)/);
  assert.ok(match, `start_process did not return a PID: ${initial}`);
  const pid = Number(match[1]);
  const result = await readProcessOutput({
    pid, timeout_ms: 15000, wait_for: 'exit', offset: -20, length: 20,
  });
  const text = result.content?.[0]?.text ?? '';
  assert.notEqual(result.isError, true, text);
  if (!/Process completed with exit code \d+/.test(text)) {
    await forceTerminate({ pid });
    throw new Error(`Shell command did not finish within the deadline: ${text}`);
  }
  return result;
}

/**
 * Check if a shell is available on the system
 */
async function isShellAvailable(shellPath) {
  if (shellPath === 'cmd' || shellPath === 'cmd.exe') return os.platform() === 'win32';
  const powershell = shellPath === 'pwsh' || shellPath === 'powershell';
  const command = powershell
    ? `${shellPath} -NoProfile -Command "Get-Host"`
    : `test -x "${shellPath}" && echo "available"`;
  const result = await runCommandToExit(command);
  const text = result.content?.[0]?.text ?? '';
  return /Process completed with exit code 0/.test(text)
    && (powershell || text.includes('available'));
}

/**
 * Get expected shell output for a given shell path
 */
function getExpectedShellOutput(shellPath) {
  switch (shellPath) {
    case '/bin/sh':
      return ['/bin/sh'];
    case '/bin/bash':
      return ['/bin/bash', 'bash'];
    case 'cmd':
    case 'cmd.exe':
      return ['cmd', 'cmd.exe'];
    case 'pwsh':
      return ['Core'];
    case 'powershell':
      return ['Desktop'];
    default:
      return [shellPath];
  }
}
/**
 * Execute echo $0 command and extract the shell name from the output
 * For Windows shells, use appropriate commands
 */
async function getShellFromCommand(shellPath = null) {
  try {
    let command = 'printf \'JDC_SHELL_VALUE:%s\\n\' "$0"';
    
    // Use different commands for Windows shells
    if (shellPath === 'cmd' || shellPath === 'cmd.exe') {
      command = 'echo JDC_SHELL_VALUE:%ComSpec%';
    } else if (shellPath === 'pwsh' || shellPath === 'powershell') {
      command = "Write-Output ('JDC_SHELL_VALUE:' + $PSVersionTable.PSEdition)";
    }
    
    const result = await runCommandToExit(command);
    
    // Extract shell name from the result
    if (result.content && result.content[0] && result.content[0].text) {
      const output = result.content[0].text;
      assert.match(output, /Process completed with exit code 0/);
      const match = output.match(/^JDC_SHELL_VALUE:([^\r\n]+)\r?$/m);
      if (match) {
        const value = match[1].trim();
        // CMD expands %ComSpec% to the executable path; unlike %0 this also
        // works when the command is launched with /c rather than a batch file.
        return shellPath === 'cmd' || shellPath === 'cmd.exe'
          ? path.win32.basename(value).toLowerCase()
          : value;
      }
    }
    
    throw new Error('Could not extract shell name from command output');
  } catch (error) {
    console.error('Error executing shell command:', error);
    throw error;
  }
}

/**
 * Setup function to prepare the test environment
 */
async function setup() {
  console.log('Setting up test environment...');
  
  // Save original config to restore later
  const originalConfig = await configManager.getConfig();
  console.log(`✓ Setup: saved original configuration`);
  console.log(`  - Original defaultShell: ${originalConfig.defaultShell || 'not set'}`);
  
  return originalConfig;
}

/**
 * Teardown function to clean up after tests
 */
async function teardown(originalConfig) {
  // Reset configuration to original
  await configManager.updateConfig(originalConfig);
  console.log('✓ Teardown: original configuration restored');
  console.log(`  - Restored defaultShell: ${originalConfig.defaultShell || 'not set'}`);
}

/**
 * Test setting defaultShell to /bin/sh
 */
async function testDefaultShellSh(t) {
  console.log('\nTest 1: Setting defaultShell to /bin/sh');
  
  // Check if /bin/sh is available
  const isAvailable = await isShellAvailable('/bin/sh');
  if (!isAvailable) {
    t.skip('/bin/sh is unavailable');
    return;
  }
  
  // Set defaultShell to /bin/sh
  await configManager.setValue('defaultShell', '/bin/sh');
  
  // Verify config was set correctly
  const config = await configManager.getConfig();
  assert.strictEqual(config.defaultShell, '/bin/sh', 'defaultShell should be set to /bin/sh');
  console.log(`✓ Configuration updated: defaultShell = ${config.defaultShell}`);
  
  // Execute echo $0 to check the shell
  const shellOutput = await getShellFromCommand(config.defaultShell);
  console.log(`✓ Command output: ${shellOutput}`);
  
  // Verify the shell is /bin/sh
  const expectedOutputs = getExpectedShellOutput('/bin/sh');
  const isValidOutput = expectedOutputs.includes(shellOutput);
  assert(isValidOutput, `Shell should be one of ${expectedOutputs.join(', ')}, got: ${shellOutput}`);
  console.log('✓ Test 1 passed: /bin/sh is correctly set as default shell');
}

/**
 * Test setting defaultShell to bash  
 */
async function testDefaultShellBash(t) {
  console.log('\nTest 2: Setting defaultShell to /bin/bash');
  
  // Check if /bin/bash is available
  const isAvailable = await isShellAvailable('/bin/bash');
  if (!isAvailable) {
    t.skip('/bin/bash is unavailable');
    return;
  }
  
  // Set defaultShell to /bin/bash (use full path)
  await configManager.setValue('defaultShell', '/bin/bash');
  
  // Verify config was set correctly
  const config = await configManager.getConfig();
  assert.strictEqual(config.defaultShell, '/bin/bash', 'defaultShell should be set to /bin/bash');
  console.log(`✓ Configuration updated: defaultShell = ${config.defaultShell}`);
  
  // Execute echo $0 to check the shell
  const shellOutput = await getShellFromCommand(config.defaultShell);
  console.log(`✓ Command output: ${shellOutput}`);
  
  // Verify the shell is /bin/bash (note: bash may show as just "bash" or full path)
  const expectedOutputs = getExpectedShellOutput('/bin/bash');
  const isValidOutput = expectedOutputs.includes(shellOutput);
  assert(isValidOutput, `Shell should be one of ${expectedOutputs.join(', ')}, got: ${shellOutput}`);
  console.log('✓ Test 2 passed: /bin/bash is correctly set as default shell');
}

/**
 * Test setting defaultShell to cmd (Windows Command Prompt)
 */
async function testDefaultShellCmd(t) {
  console.log('\nTest 3: Setting defaultShell to cmd');
  
  // Check if cmd is available (Windows only)
  const isAvailable = await isShellAvailable('cmd');
  if (!isAvailable) {
    t.skip('cmd is unavailable');
    return;
  }
  
  // Set defaultShell to cmd
  await configManager.setValue('defaultShell', 'cmd');
  
  // Verify config was set correctly
  const config = await configManager.getConfig();
  assert.strictEqual(config.defaultShell, 'cmd', 'defaultShell should be set to cmd');
  console.log(`✓ Configuration updated: defaultShell = ${config.defaultShell}`);
  
  // Execute echo %0 to check the shell (Windows command)
  const shellOutput = await getShellFromCommand('cmd');
  console.log(`✓ Command output: ${shellOutput}`);
  
  // Verify the shell is cmd
  const expectedOutputs = getExpectedShellOutput('cmd');
  const isValidOutput = expectedOutputs.includes(shellOutput);
  assert(isValidOutput, `Shell should be one of ${expectedOutputs.join(', ')}, got: ${shellOutput}`);
  console.log('✓ Test 3 passed: cmd is correctly set as default shell');
}

/**
 * Test setting defaultShell to pwsh (PowerShell Core)
 */
async function testDefaultShellPwsh(t) {
  console.log('\nTest 4: Setting defaultShell to pwsh');
  
  // Check if pwsh is available
  const isAvailable = await isShellAvailable('pwsh');
  if (!isAvailable) {
    t.skip('PowerShell Core is unavailable');
    return;
  }
  
  // Set defaultShell to pwsh
  await configManager.setValue('defaultShell', 'pwsh');
  
  // Verify config was set correctly
  const config = await configManager.getConfig();
  assert.strictEqual(config.defaultShell, 'pwsh', 'defaultShell should be set to pwsh');
  console.log(`✓ Configuration updated: defaultShell = ${config.defaultShell}`);
  
  // Execute PowerShell command to check the shell
  const shellOutput = await getShellFromCommand('pwsh');
  console.log(`✓ Command output: ${shellOutput}`);
  
  // Verify the shell is pwsh
  const expectedOutputs = getExpectedShellOutput('pwsh');
  const isValidOutput = expectedOutputs.includes(shellOutput);
  assert(isValidOutput, `Shell should be one of ${expectedOutputs.join(', ')}, got: ${shellOutput}`);
  console.log('✓ Test 4 passed: pwsh is correctly set as default shell');
}
/**
 * Test switching between different shells
 */
async function testShellSwitching(t) {
  console.log('\nTest 5: Testing shell switching');
  
  // Get available shells for switching test
  const availableShells = [];
  if (await isShellAvailable('/bin/sh')) availableShells.push('/bin/sh');
  if (await isShellAvailable('/bin/bash')) availableShells.push('/bin/bash');
  if (await isShellAvailable('cmd')) availableShells.push('cmd');
  if (await isShellAvailable('pwsh')) availableShells.push('pwsh');
  
  if (availableShells.length < 2) {
    t.skip('at least two shells are required');
    return;
  }
  
  console.log(`✓ Available shells for switching test: ${availableShells.join(', ')}`);
  
  // Test switching between first two available shells
  const shell1 = availableShells[0];
  const shell2 = availableShells[1];
  
  // Switch to first shell
  await configManager.setValue('defaultShell', shell1);
  let shellOutput = await getShellFromCommand(shell1);
  let expectedOutputs = getExpectedShellOutput(shell1);
  let isValidOutput = expectedOutputs.includes(shellOutput);
  assert(isValidOutput, `Switch to ${shell1} should work, got: ${shellOutput}`);
  console.log(`✓ Successfully switched to ${shell1}: ${shellOutput}`);
  
  // Switch to second shell
  await configManager.setValue('defaultShell', shell2);
  shellOutput = await getShellFromCommand(shell2);
  expectedOutputs = getExpectedShellOutput(shell2);
  isValidOutput = expectedOutputs.includes(shellOutput);
  assert(isValidOutput, `Switch to ${shell2} should work, got: ${shellOutput}`);
  console.log(`✓ Successfully switched to ${shell2}: ${shellOutput}`);
  
  // Switch back to first shell
  await configManager.setValue('defaultShell', shell1);
  shellOutput = await getShellFromCommand(shell1);
  expectedOutputs = getExpectedShellOutput(shell1);
  isValidOutput = expectedOutputs.includes(shellOutput);
  assert(isValidOutput, `Switch back to ${shell1} should work, got: ${shellOutput}`);
  console.log(`✓ Successfully switched back to ${shell1}: ${shellOutput}`);
  
  console.log('✓ Test 5 passed: shell switching works correctly');
}

/**
 * Test that configuration changes persist
 */
async function testConfigurationPersistence(t) {
  console.log('\nTest 6: Testing configuration persistence');
  
  // Find an available shell for testing
  let testShell = '/bin/sh';
  if (!(await isShellAvailable('/bin/sh'))) {
    if (await isShellAvailable('/bin/bash')) {
      testShell = '/bin/bash';
    } else if (await isShellAvailable('cmd')) {
      testShell = 'cmd';
    } else if (await isShellAvailable('pwsh')) {
      testShell = 'pwsh';
    } else {
      t.skip('no supported shell is available');
      return;
    }
  }
  
  // Set defaultShell to the test shell
  await configManager.setValue('defaultShell', testShell);
  
  // Get config multiple times to ensure it persists
  const config1 = await configManager.getConfig();
  const config2 = await configManager.getConfig();
  
  assert.strictEqual(config1.defaultShell, testShell, 'Configuration should persist on first read');
  assert.strictEqual(config2.defaultShell, testShell, 'Configuration should persist on second read');
  assert.strictEqual(config1.defaultShell, config2.defaultShell, 'Configuration should be consistent across reads');
  
  console.log(`✓ Configuration persists correctly: ${config1.defaultShell}`);
  console.log('✓ Test 6 passed: configuration persistence works correctly');
}

let originalConfig;
before(async () => { originalConfig = await setup(); });
after(async () => { if (originalConfig) await teardown(originalConfig); });

test('default shell selects /bin/sh', testDefaultShellSh);
test('default shell selects /bin/bash', testDefaultShellBash);
test('default shell selects cmd', testDefaultShellCmd);
test('default shell selects PowerShell Core', testDefaultShellPwsh);
test('default shell switching changes the executing shell', testShellSwitching);
test('default shell configuration persists', testConfigurationPersistence);
test('delayed shell output is read after the process exits', async () => {
  const shell = os.platform() === 'win32' ? 'cmd.exe' : '/bin/sh';
  // Native shell commands avoid nested executable quoting on Windows hosts
  // where Node is installed beneath a path containing spaces.
  const command = os.platform() === 'win32'
    ? 'ping -n 2 127.0.0.1 >nul && echo JDC_DELAYED_SHELL_MARKER'
    : "sleep 1 && printf 'JDC_DELAYED_SHELL_MARKER\\n'";
  const result = await runCommandToExit(command, 20, shell);
  const output = result.content?.[0]?.text ?? '';
  assert.notEqual(result.isError, true, output);
  assert.match(output, /Process completed with exit code 0/);
  assert.match(output, /JDC_DELAYED_SHELL_MARKER/);
});
