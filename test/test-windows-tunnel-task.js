import assert from 'node:assert/strict';

import {
  buildWindowsTunnelTaskXml,
  buildSchtasksCreateArgs,
  encodeWindowsTaskXml,
} from '../dist/platform/windows/tunnel-task.js';

const base = {
  author: 'DESKTOP-TEST\\Roy',
  executable: 'C:\\Program Files\\OpenAI\\tunnel-client.exe',
  profileDir: 'C:\\Users\\Roy\\AppData\\Local\\OpenAI\\tunnel-client\\profiles',
  profileName: 'desktop-commander-poc',
};

const xml = buildWindowsTunnelTaskXml(base);
const encodedXml = encodeWindowsTaskXml(xml);

assert.equal(encodedXml[0], 0xff);
assert.equal(encodedXml[1], 0xfe);
assert.equal(encodedXml.subarray(2).toString('utf16le'), xml);

assert.match(xml, /<LogonType>S4U<\/LogonType>/);
assert.match(xml, /<RunLevel>LeastPrivilege<\/RunLevel>/);
assert.match(xml, /<BootTrigger>[\s\S]*<Enabled>true<\/Enabled>[\s\S]*<\/BootTrigger>/);
assert.match(xml, /<MultipleInstancesPolicy>IgnoreNew<\/MultipleInstancesPolicy>/);
assert.match(xml, /<RestartOnFailure>[\s\S]*<Interval>PT1M<\/Interval>[\s\S]*<Count>5<\/Count>[\s\S]*<\/RestartOnFailure>/);
assert.match(xml, /<ExecutionTimeLimit>PT0S<\/ExecutionTimeLimit>/);
assert.match(xml, /<Command>C:\\Program Files\\OpenAI\\tunnel-client\.exe<\/Command>/);
assert.match(
  xml,
  /<Arguments>run --profile-dir &quot;C:\\Users\\Roy\\AppData\\Local\\OpenAI\\tunnel-client\\profiles&quot; --profile desktop-commander-poc<\/Arguments>/,
);
assert.doesNotMatch(xml, /password/i);
assert.doesNotMatch(xml, /powershell|cmd\.exe|wscript|cscript/i);

const createArgs = buildSchtasksCreateArgs('Desktop Commander Windows Tunnel', 'C:\\Temp\\jdc-task.xml');
assert.deepEqual(createArgs, [
  '/Create',
  '/TN',
  'Desktop Commander Windows Tunnel',
  '/XML',
  'C:\\Temp\\jdc-task.xml',
  '/F',
]);

const failClosedCreateArgs = buildSchtasksCreateArgs(
  'Desktop Commander Windows Tunnel',
  'C:\\Temp\\jdc-task.xml',
  false,
);
assert.deepEqual(failClosedCreateArgs, [
  '/Create',
  '/TN',
  'Desktop Commander Windows Tunnel',
  '/XML',
  'C:\\Temp\\jdc-task.xml',
]);

const escaped = buildWindowsTunnelTaskXml({
  ...base,
  author: 'DOMAIN\\A&B',
  profileName: 'profile-1',
});
assert.match(escaped, /DOMAIN\\A&amp;B/);

assert.throws(
  () =>
    buildWindowsTunnelTaskXml({
      ...base,
      executable: 'tunnel-client.exe',
    }),
  /absolute Windows path/i,
);

assert.throws(
  () =>
    buildWindowsTunnelTaskXml({
      ...base,
      profileName: 'bad profile',
    }),
  /profile name/i,
);

console.log('Windows tunnel Task Scheduler contract: PASS');
