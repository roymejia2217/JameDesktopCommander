import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const workflowPath = '.github/workflows/t011-capability-feasibility.yml';
const acceptancePath = 'test/security/t011-linux-issuer-read-e2e.sh';
const serviceProbePath = 'native/authority-service/examples/linux_issuer_read_probe.rs';
const fixturePath = 'native/authority-store/examples/issuer_read_fixture.rs';

test('T011 Linux issuer read E2E is wired to real OS principals without production activation', async () => {
  const [workflow, acceptance, probe, fixture] = await Promise.all([
    readFile(workflowPath, 'utf8'),
    readFile(acceptancePath, 'utf8'),
    readFile(serviceProbePath, 'utf8'),
    readFile(fixturePath, 'utf8'),
  ]);

  assert.match(workflow, /shellcheck --severity=warning test\/security\/t011-linux-issuer-read-e2e\.sh/);
  assert.match(workflow, /bash test\/security\/t011-linux-issuer-read-e2e\.sh/);
  assert.ok(
    workflow.indexOf('Compile the original TypeScript C4d validator') <
      workflow.indexOf('Prove real Node principal receives issuer-owned handle-bound bytes'),
    'the E2E must run only after the production TypeScript contract has been compiled',
  );
  assert.match(acceptance, /sudo -n -u jdc-mcp-client -- node --input-type=module/);
  assert.match(acceptance, /encodeAuthorityRequestFrame/);
  assert.match(acceptance, /decodeAuthorityReadReplyFrame/);
  assert.match(acceptance, /dist\/security\/authority-frame-contract\.js/);
  assert.match(acceptance, /"kind":"read-file"/);
  assert.match(acceptance, /SELECT hex\(epoch\), hex\(request\) FROM replay_claims/);
  assert.match(acceptance, /jdc-authority\.service\.d\/read-e2e\.conf/);
  assert.match(probe, /dispatch_one_inherited_read_reply/);
  assert.match(fixture, /PolicyBytesStore/);
  assert.match(fixture, /replay_claims/);

  const productionMain = await readFile('native/authority-service/src/main.rs', 'utf8');
  assert.match(productionMain, /eprintln!\("E_POLICY_UNAVAILABLE"\)/);
  assert.doesNotMatch(productionMain, /dispatch_one_inherited_read_reply/);
});
