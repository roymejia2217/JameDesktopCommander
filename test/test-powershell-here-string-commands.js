import assert from 'node:assert/strict';
import { test } from 'node:test';
import { commandManager } from '../dist/command-manager.js';

const blocked = new Set(['netsh', 'reg', 'firewall']);

function hasBlockedCommand(source) {
  return commandManager.extractCommands(source).some((name) => blocked.has(name));
}

test('read-only regex alternatives in PowerShell here-strings are not commands', () => {
  const wrapped = String.raw`$payload=@'
& git -C 'E:\Proyectos\JameFirewall' grep -n -E 'New-NetFirewallRule|Remove-NetFirewallRule|netsh|Stopwatch' -- src | Select-Object -First 3
'@
Invoke-Expression $payload`;
  assert.equal(hasBlockedCommand(wrapped), false);
  assert.equal(hasBlockedCommand(String.raw`& git grep -E 'netsh|Stopwatch' -- src`), false);
});

test('literal here-string with a blocked command on its own line is denied', () => {
  const wrapped = String.raw`$payload=@'
Write-Output 'hello'
netsh
'@
Invoke-Expression $payload`;
  assert.equal(hasBlockedCommand(wrapped), true);
});

test('expanded here-string with executable substitution is denied', () => {
  const wrapped = String.raw`$payload=@"
Write-Output "$(netsh)"
"@
Invoke-Expression $payload`;
  assert.equal(hasBlockedCommand(wrapped), true);
});

test('CRLF multiline command blocks remain denied', () => {
  const source = ["$payload=@'", "Write-Output 'safe'", "reg", "'@", "Invoke-Expression $payload"].join('\r\n');
  assert.equal(hasBlockedCommand(source), true);
});

test('second independent here-string cannot conceal a forbidden command', () => {
  const source = String.raw`$first=@'
Write-Output 'safe'
'@
$second=@'
firewall
'@
Invoke-Expression $second`;
  assert.equal(hasBlockedCommand(source), true);
});

test('commands after a closing here-string remain subject to denylist', () => {
  const source = String.raw`$payload=@'
Write-Output safe
'@
Write-Output 'done'
netsh`;
  assert.equal(hasBlockedCommand(source), true);
});

test('CRLF regex alternatives are not interpreted as shell commands', () => {
  const source = ["$payload=@'", "& git grep -E 'New-NetFirewallRule|Remove-NetFirewallRule|netsh|Stopwatch' -- src", "'@", "Invoke-Expression $payload"].join('\r\n');
  assert.equal(hasBlockedCommand(source), false);
});

test('existing blocked command handling remains unchanged outside here-strings', () => {
  assert.equal(hasBlockedCommand('Write-Output ok; netsh'), true);
  assert.equal(hasBlockedCommand('echo "$(netsh)"'), true);
  assert.equal(hasBlockedCommand('echo "netsh|reg"'), false);
  assert.equal(hasBlockedCommand('/usr/bin/sudo echo ok'), false);
});
