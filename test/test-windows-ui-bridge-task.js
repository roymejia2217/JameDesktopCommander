import assert from 'node:assert/strict';

import { buildWindowsUiBridgeTaskXml } from '../dist/platform/windows/ui-bridge-task.js';

const base = {
  author: 'DESKTOP-TEST\\Roy',
  executable: 'C:\\Users\\Roy\\AppData\\Local\\JameDesktopCommander\\ui-bridge\\DesktopCommander.UiBridge.exe',
};

const xml = buildWindowsUiBridgeTaskXml(base);

assert.match(xml, /<LogonType>InteractiveToken<\/LogonType>/);
assert.match(xml, /<RunLevel>LeastPrivilege<\/RunLevel>/);
assert.match(
  xml,
  /<LogonTrigger>[\s\S]*<Enabled>true<\/Enabled>[\s\S]*<UserId>DESKTOP-TEST\\Roy<\/UserId>[\s\S]*<\/LogonTrigger>/,
);
assert.doesNotMatch(xml, /<BootTrigger>/);
assert.doesNotMatch(xml, /<LogonType>S4U<\/LogonType>/);
assert.match(xml, /<MultipleInstancesPolicy>IgnoreNew<\/MultipleInstancesPolicy>/);
assert.match(xml, /<ExecutionTimeLimit>PT0S<\/ExecutionTimeLimit>/);
assert.match(
  xml,
  /<RestartOnFailure>[\s\S]*<Interval>PT1M<\/Interval>[\s\S]*<Count>5<\/Count>[\s\S]*<\/RestartOnFailure>/,
);
assert.match(
  xml,
  /<Command>C:\\Users\\Roy\\AppData\\Local\\JameDesktopCommander\\ui-bridge\\DesktopCommander\.UiBridge\.exe<\/Command>/,
);
assert.match(
  xml,
  /<WorkingDirectory>C:\\Users\\Roy\\AppData\\Local\\JameDesktopCommander\\ui-bridge<\/WorkingDirectory>/,
);
assert.doesNotMatch(xml, /<Arguments>/);
assert.doesNotMatch(xml, /powershell|cmd\.exe|wscript|cscript/i);

const escaped = buildWindowsUiBridgeTaskXml({
  ...base,
  author: 'DOMAIN\\A&B',
});
assert.match(escaped, /DOMAIN\\A&amp;B/);

assert.throws(
  () =>
    buildWindowsUiBridgeTaskXml({
      ...base,
      executable: 'DesktopCommander.UiBridge.exe',
    }),
  /absolute Windows path/i,
);

console.log('Windows UI bridge Task Scheduler contract: PASS');
