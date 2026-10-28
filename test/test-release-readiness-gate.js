import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const workflow = readFileSync(join(root, '.github/workflows/release.yml'), 'utf8')
  .replace(/\r\n/g, '\n');
function extractGuardScript() {
  const anchor = '      - name: Verify production release readiness\n';
  assert.ok(workflow.includes(anchor), 'release must have a readiness gate');
  const body = workflow.split(anchor)[1].split('\n      - name:')[0];
  const scriptMarker = '          script: |\n';
  assert.ok(body.includes(scriptMarker), 'readiness gate must use github-script');
  const script = body.split(scriptMarker)[1].split('\n')
    .filter(line => line.trim() !== '')
    .map(line => {
      assert.ok(line.startsWith('            '), 'script indentation changed');
      return line.slice(12);
    }).join('\n');
  return script;
}
async function runGate({ approval = 'true', states = {}, failOn = null } = {}) {
  const previous = process.env.JDC_PRODUCTION_RELEASE_APPROVED;
  process.env.JDC_PRODUCTION_RELEASE_APPROVED = approval;
  const outputs = new Map(), notices = [], calls = [];
  const core = {
    setOutput: (name, value) => outputs.set(name, value),
    notice: message => notices.push(message),
  };
  const github = { rest: { issues: { get: async ({ owner, repo, issue_number }) => {
    assert.equal(owner, 'roymejia2217');
    assert.equal(repo, 'JameDesktopCommander');
    calls.push(issue_number);
    if (issue_number === failOn) throw Error('API unreachable');
    return { data: states[issue_number] ?? { state: 'open' } };
  } } } };
  try {
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    await new AsyncFunction('github', 'context', 'core', extractGuardScript())(
      github, { repo: { owner: 'roymejia2217', repo: 'JameDesktopCommander' } }, core);
  } finally {
    if (previous === undefined) delete process.env.JDC_PRODUCTION_RELEASE_APPROVED;
    else process.env.JDC_PRODUCTION_RELEASE_APPROVED = previous;
  }
  return { outputs, notices, calls };
}
test('release job requires explicit approval and guards both mutation steps', () => {
  assert.match(workflow, /JDC_PRODUCTION_RELEASE_APPROVED/);
  assert.match(workflow, /- name: Create scoped release GitHub App token\n\s+if: steps\.readiness\.outputs\.eligible == 'true'/);
  assert.match(workflow, /- name: Run Release Please\n\s+if: steps\.readiness\.outputs\.eligible == 'true'/);
});

test('missing manual approval fails closed without API access', async () => {
  for (const approval of ['', 'false', 'TRUE', 'unexpected']) {
    const result = await runGate({ approval });
    assert.equal(result.outputs.get('eligible'), 'false');
    assert.equal(result.calls.length, 0);
  }
});

test('every P0 is checked and any open issue defers release', async () => {
  const states = { 124: { state: 'closed' }, 139: { state: 'open' },
    148: { state: 'closed' } };
  const result = await runGate({ states });
  assert.deepEqual(result.calls, [124, 139, 148]);
  assert.equal(result.outputs.get('eligible'), 'false');
  assert.ok(result.notices.some(message => message.includes('139')));
});
test('release is eligible only when all blockers are closed and approval is explicit', async () => {
  const closed = { state: 'closed' };
  const result = await runGate({ states: { 124: closed, 139: closed, 148: closed } });
  assert.deepEqual(result.calls, [124, 139, 148]);
  assert.equal(result.outputs.get('eligible'), 'true');
});

test('unavailable GitHub issue or API failure cannot grant release eligibility', async () => {
  const result = await runGate({ states: {
    124: { state: 'closed' }, 139: { state: 'closed' }, 148: null,
  } });
  assert.equal(result.outputs.get('eligible'), 'false');
  await assert.rejects(runGate({ failOn: 139 }), /API unreachable/);
});
