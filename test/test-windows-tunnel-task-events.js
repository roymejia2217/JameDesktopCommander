import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
    buildWindowsTunnelTaskEventsPowerShell,
    parseWindowsTunnelTaskEvents,
    readWindowsTunnelTaskEvents,
} from '../dist/platform/windows/tunnel-task-events.js';
import {
    runWindowsTunnelCommand,
    formatWindowsTunnelCommandResult,
} from '../dist/npm-scripts/tunnel.js';

const fixture = {
    kind: 'observational_only',
    capped: false,
    events: [
        { timeUtc: '2026-10-22T22:00:58.0000000Z', eventId: 201, resultCode: '2147942401' },
        { timeUtc: '2026-10-22T22:00:58.0000000Z', eventId: 102, resultCode: null },
    ],
};

test('Task Scheduler history exposes allowlisted observations, not raw event data', () => {
    assert.deepEqual(parseWindowsTunnelTaskEvents(JSON.stringify(fixture)), fixture);
    assert.doesNotMatch(JSON.stringify(parseWindowsTunnelTaskEvents(JSON.stringify(fixture))),
        /device|token|profile|path|command/);
});

test('reject forged health, unwanted identity fields, unknown event IDs, invalid codes and timestamps', () => {
    for (const bad of [
        null, [], 'not json', {}, { ...fixture, kind: 'ready' },
        { ...fixture, deviceId: 'SECRET' },
        { ...fixture, events: [{ ...fixture.events[0], taskName: 'SECRET' }] },
        { ...fixture, events: [{ ...fixture.events[0], resultCode: '4294967296' }] },
        { ...fixture, events: [{ ...fixture.events[0], resultCode: '-1' }] },
        { ...fixture, events: [{ ...fixture.events[0], resultCode: 'secret' }] },
        { ...fixture, events: [{ ...fixture.events[0], eventId: 666 }] },
        { ...fixture, events: [{ ...fixture.events[0], timeUtc: 'tomorrow' }] },
        { ...fixture, events: Array.from({ length: 51 }, () => fixture.events[0]) },
    ]) {
        assert.throws(() => parseWindowsTunnelTaskEvents(
            typeof bad === 'string' ? bad : JSON.stringify(bad),
        ));
    }
});

test('empty, capped and invalid envelopes remain observational only', () => {
    assert.deepEqual(parseWindowsTunnelTaskEvents(JSON.stringify({ ...fixture, events: [] })),
        { ...fixture, events: [] });
    assert.equal(parseWindowsTunnelTaskEvents(
        JSON.stringify({ ...fixture, capped: true })).capped, true);
    for (const bad of [
        { ...fixture, capped: 'false' },
        { ...fixture, events: 'none' },
        { ...fixture, events: [{ ...fixture.events[0], resultCode: 1 }] },
    ]) {
        assert.throws(() => parseWindowsTunnelTaskEvents(JSON.stringify(bad)));
    }
});

test('query is bounded, read-only, safely quotes task names and excludes raw messages', () => {
    const source = buildWindowsTunnelTaskEventsPowerShell("Tunnel's task");
    assert.match(source, /Get-WinEvent/);
    assert.match(source, /-MaxEvents 5000/);
    assert.match(source, /\.AddHours\(-72\)/);
    assert.match(source, /Tunnel''s task/);
    assert.match(source, /ConvertTo-Json/);
    assert.match(source, /\$matched\.Count -gt 50/);
    assert.doesNotMatch(source,
        /Start-ScheduledTask|Stop-ScheduledTask|Register-ScheduledTask|Remove-Item|Invoke-Expression/);
    assert.throws(() => buildWindowsTunnelTaskEventsPowerShell('bad\r\nname'));
});

test('only OS PowerShell is used, with a bounded single invocation', async () => {
    let count = 0;
    const found = await readWindowsTunnelTaskEvents('Desktop Commander Windows Tunnel', {
        platform: 'win32',
        environment: { SystemRoot: 'C:\\Windows' },
        run: async (executable, args) => {
            count++;
            assert.equal(executable.toLowerCase(),
                'c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe');
            assert.deepEqual(args.slice(0, 3), ['-NoLogo', '-NoProfile', '-NonInteractive']);
            assert.equal(args[3], '-EncodedCommand');
            assert.match(Buffer.from(args[4], 'base64').toString('utf16le'), /Get-WinEvent/);
            return { stdout: JSON.stringify(fixture), stderr: '' };
        },
    });
    assert.equal(count, 1);
    assert.deepEqual(found, fixture);
});

test('reject unsupported OS and invalid SystemRoot before any invocation', async () => {
    let calls = 0;
    const run = async () => { calls++; return { stdout: '{}', stderr: '' }; };
    for (const deps of [
        { platform: 'linux', environment: { SystemRoot: 'C:\\Windows' }, run },
        { platform: 'win32', environment: { SystemRoot: 'Windows' }, run },
    ]) {
        await assert.rejects(readWindowsTunnelTaskEvents('Desktop Commander Windows Tunnel', deps));
    }
    assert.equal(calls, 0);
});

test('CLI events works while tunnel status endpoint is unavailable; no start/stop performed', async () => {
    const result = await runWindowsTunnelCommand(['events'], {
        platform: 'win32',
        statusTunnel: async () => { throw new Error('OFFLINE'); },
        taskEvents: async (name) => {
            assert.equal(name, 'Desktop Commander Windows Tunnel');
            return fixture;
        },
        startTask: async () => { throw new Error('unexpected start'); },
        stopTask: async () => { throw new Error('unexpected stop'); },
    });
    assert.equal(result.action, 'events');
    assert.deepEqual(result.history, fixture);
    assert.doesNotMatch(formatWindowsTunnelCommandResult(result),
        /profile|device|secret|OFFLINE/);
    await assert.rejects(runWindowsTunnelCommand(['events', '--extra'], {
        platform: 'win32',
        taskEvents: async () => fixture,
    }), /does not accept additional arguments/);
});
