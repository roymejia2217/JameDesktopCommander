import assert from 'node:assert/strict';
import { OpenCodeReadArgsSchema, OpenCodeTaskArgsSchema } from '../dist/tools/schemas.js';
import { handleOpenCodeRead } from '../dist/tools/opencode.js';

assert.equal(OpenCodeReadArgsSchema.safeParse({ action: 'health' }).success, true);
assert.equal(OpenCodeReadArgsSchema.safeParse({ action: 'status', project: 'jamefirewall' }).success, false);
assert.equal(OpenCodeTaskArgsSchema.safeParse({ action: 'run', project: 'jamefirewall' }).success, false);
assert.equal(
    OpenCodeTaskArgsSchema.safeParse({
        action: 'continue',
        project: 'jamefirewall',
        sessionId: 'ses_test',
        prompt: 'continue safely',
    }).success,
    true,
);

// Alias-only tools must fail closed on caller-supplied directories or other
// unrecognized selectors instead of silently stripping them.
assert.equal(OpenCodeReadArgsSchema.safeParse({
    action: 'status', project: 'test-project', sessionId: 'ses_valid',
    workingDirectory: 'unapproved-directory',
}).success, false);
assert.equal(OpenCodeTaskArgsSchema.safeParse({
    action: 'run', project: 'test-project', prompt: 'synthetic',
    cwd: 'unapproved-directory',
}).success, false);
assert.equal(OpenCodeTaskArgsSchema.safeParse({
    action: 'run', project: 'test-project', prompt: 'synthetic',
    directory: 'unapproved-directory',
}).success, false);

const previousUrl = process.env.OPENCODE_GATEWAY_RDC_URL;
const previousToken = process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN;
try {
    process.env.OPENCODE_GATEWAY_RDC_URL = 'https://example.com/rdc-mcp';
    process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN = 'A'.repeat(43);
    await assert.rejects(
        () => handleOpenCodeRead({ action: 'health' }),
        /loopback HTTP \/rdc-mcp/,
    );
} finally {
    if (previousUrl === undefined) delete process.env.OPENCODE_GATEWAY_RDC_URL;
    else process.env.OPENCODE_GATEWAY_RDC_URL = previousUrl;
    if (previousToken === undefined) delete process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN;
    else process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN = previousToken;
}

console.log('OpenCode native tool boundary tests passed.');
