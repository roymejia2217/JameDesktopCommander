import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { resolve, dirname } from 'node:path';
import { DesktopCommanderIntegration } from '../dist/remote-device/desktop-commander-integration.js';

test('remote host resolves the server from its own packaged runtime', async () => {
    const config = await new DesktopCommanderIntegration().resolveMcpConfig();
    const entry = resolve('dist/index.js');
    assert.deepEqual(config, {
        command: process.execPath, args: [entry], cwd: dirname(entry),
    });
});

test('missing packaged entry must not discover or launch an ambient executable', async (t) => {
    const missing = async () => { throw Object.assign(new Error('missing'), { code: 'ENOENT' }); };
    t.mock.method(fs, 'access', missing);
    t.mock.method(fs, 'lstat', missing);
    const discovery = t.mock.method(childProcess, 'spawn', () => {
        const child = new EventEmitter();
        queueMicrotask(() => child.emit('close', 0));
        return child;
    });
    syncBuiltinESMExports();
    try {
        const config = await new DesktopCommanderIntegration().resolveMcpConfig();
        assert.equal(config, null, 'missing packaged entry must fail closed');
        assert.equal(discovery.mock.callCount(), 0, 'no ambient PATH lookup');
    } finally {
        t.mock.restoreAll();
        syncBuiltinESMExports();
    }
});

test('non-regular or inaccessible entry is rejected before MCP initialization', async (t) => {
    const integration = new DesktopCommanderIntegration();
    for (const entry of [
        { isFile: () => false, isDirectory: () => true },
        { isFile: () => false, isSymbolicLink: () => true },
    ]) {
        const stat = t.mock.method(fs, 'lstat', async () => entry);
        try {
            assert.equal(await integration.resolveMcpConfig(), null);
            await assert.rejects(integration.initialize(), /E_LOCAL_MCP_RUNTIME_UNAVAILABLE/);
            assert.equal(integration.ready, false);
        } finally {
            stat.mock.restore();
        }
    }
    const stat = t.mock.method(fs, 'lstat', async () => {
        throw Object.assign(new Error('unreadable'), { code: 'EACCES' });
    });
    try {
        await assert.rejects(integration.initialize(), /E_LOCAL_MCP_RUNTIME_UNAVAILABLE/);
        assert.equal(integration.ready, false);
    } finally {
        stat.mock.restore();
    }
});
