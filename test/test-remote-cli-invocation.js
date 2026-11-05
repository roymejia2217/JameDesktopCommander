import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatLocalRemoteCommand } from '../src/remote-device/local-cli-invocation.ts';

test('Windows PowerShell commands use the executable and entrypoint actually running JDC', () => {
  const cmd = formatLocalRemoteCommand({
    platform: 'win32',
    executable: 'C:\\Program Files\\nodejs\\node.exe',
    entrypoint: 'E:\\JDC Private\\dist\\index.js',
    option: '--help',
  });
  assert.equal(cmd, "& 'C:\\Program Files\\nodejs\\node.exe' 'E:\\JDC Private\\dist\\index.js' remote --help");
  assert.doesNotMatch(cmd, /npx|wonderwhy-er|latest/i);
});

test('Linux sh command quotes spaces and metacharacters without implying npm installation', () => {
  const cmd = formatLocalRemoteCommand({
    platform: 'linux',
    executable: "/opt/it's $HOME/bin/node",
    entrypoint: '/home/roy/JDC portables/dist/index.js',
    option: '--logout',
  });
  assert.equal(cmd, "'/opt/it'\\''s $HOME/bin/node' '/home/roy/JDC portables/dist/index.js' remote --logout");
  assert.doesNotMatch(cmd, /npx|wonderwhy-er|latest/);
});

test('rejects malformed paths, newlines, or arbitrary remote args in examples', () => {
  const ok = { platform: 'linux', executable: '/usr/bin/node', entrypoint: '/tmp/jdc/index.js', option: '--debug' };
  for (const patch of [
    { executable: '' }, { entrypoint: '' },
    { executable: '/bin/node\necho secret' }, { entrypoint: '/tmp/x\rmessage' },
    { option: '--logout;echo BAD' }, { option: '--no-persist-session' },
  ]) assert.throws(() => formatLocalRemoteCommand({ ...ok, ...patch }), /Invalid local JDC command/);
});

test('allowed examples are explicit remote commands on the current process', () => {
  for (const option of ['', '--help', '--debug', '--logout']) {
    const cmd = formatLocalRemoteCommand({
      platform: 'win32', executable: 'C:\\Portable\\node.exe',
      entrypoint: 'C:\\Portable\\dist\\index.js', option,
    });
    assert.ok(cmd.includes(" 'C:\\Portable\\dist\\index.js' remote"));
    if (option) assert.ok(cmd.endsWith(option)); else assert.ok(cmd.endsWith('remote'));
  }
});
