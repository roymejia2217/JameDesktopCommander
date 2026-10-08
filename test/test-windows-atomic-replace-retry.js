import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { test } from 'node:test';
const targetModule = new URL('../dist/utils/windows-atomic-replace.js', import.meta.url).href;

test('Win32 ReplaceFileW retries only error 1175, with a finite bound', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const koffi = createRequire(targetModule)('koffi').default;
  const originalLoad = koffi.load;
  const scenario = { win32Code: 1175, succeedOn: 3, calls: 0 };
  koffi.load = () => ({
    func: (_abi, name) => {
      if (name === 'ReplaceFileW') {
        return () => (++scenario.calls >= scenario.succeedOn ? 1 : 0);
      }
      if (name === 'GetLastError') return () => scenario.win32Code;
      throw new Error(`Unexpected Win32 function: ${name}`);
    },
  });
  try {
    const { replaceFileWin32 } = await import(targetModule);
    const invoke = () => replaceFileWin32('C:\\test\\target.json', 'C:\\test\\replacement.json');
    const arrange = (win32Code, succeedOn) => {
      scenario.win32Code = win32Code;
      scenario.succeedOn = succeedOn;
      scenario.calls = 0;
    };

    await t.test('1175 resolves when a later attempt succeeds', async () => {
      arrange(1175, 3);
      await invoke();
      assert.equal(scenario.calls, 3);
    });

    await t.test('persistent 1175 stops after the bounded retry budget', async () => {
      arrange(1175, Number.POSITIVE_INFINITY);
      await assert.rejects(invoke(), (error) =>
        error.code === 'EBUSY' && error.win32Code === 1175);
      assert.equal(scenario.calls, 50);
    });
    for (const code of [1176, 1177, 1234]) {
      await t.test(`Win32 error ${code} fails immediately without retries`, async () => {
        arrange(code, Number.POSITIVE_INFINITY);
        await assert.rejects(invoke(), (error) =>
          error.code === 'EIO' && error.win32Code === code);
        assert.equal(scenario.calls, 1);
      });
    }

    await t.test('normal immediate success does not retry', async () => {
      arrange(1175, 1);
      await invoke();
      assert.equal(scenario.calls, 1);
    });
  } finally {
    koffi.load = originalLoad;
  }
});
