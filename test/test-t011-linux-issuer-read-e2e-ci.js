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
  assert.match(acceptance, /node_binary="\$\(realpath -e -- "\$\(command -v node\)"\)"/);
  assert.match(acceptance, /sudo -n -u jdc-mcp-client -- "\$node_binary" --version/);
  assert.match(acceptance, /sudo -n -u jdc-mcp-client -- "\$node_binary" --input-type=module/);
  assert.doesNotMatch(acceptance, /sudo -n -u jdc-mcp-client -- node(?:\s|$)/m);
  assert.match(acceptance, /requestIssuerOwnedRead/);
  assert.doesNotMatch(acceptance, /net\.createConnection/);
  assert.match(acceptance, /requestIssuerOwnedRead/);
  assert.match(acceptance, /installed_read_client/);
  assert.match(acceptance, /authority-read-client[.]mjs/);
  assert.match(acceptance, /contract_dir='\/usr\/libexec\/jdc\/read-e2e-contract'/);
  assert.match(acceptance, /authority-frame-contract\.js/);
  assert.match(acceptance, /authority-operation-contract\.js/);
  assert.match(acceptance, /install -d -o root -g root -m 0755 -- "\$contract_dir"/);
  assert.match(acceptance, /install -o root -g root -m 0644 -- "\$contract_source" "\$installed_contract"/);
  assert.match(acceptance, /cmp -s -- "\$contract_source" "\$installed_contract"/);
  assert.match(acceptance, /sudo -n -u jdc-mcp-client -- test -r "\$installed_contract"/);
  assert.doesNotMatch(acceptance, /contract="\$\(realpath -e -- dist\/security\/authority-frame-contract\.js\)"/);
  assert.match(acceptance, /"kind":"read-file"/);
  assert.match(acceptance, /SELECT hex\(epoch\), hex\(request\) FROM replay_claims/);
  assert.match(acceptance, /jdc-authority\.service\.d\/read-e2e\.conf/);
  assert.match(probe, /dispatch_one_inherited_readonly_reply/);
  assert.doesNotMatch(probe, /dispatch_one_inherited_read_reply/);
  assert.match(probe, /for _ in 0\.\.2/);
  assert.match(acceptance, /T011_ISSUER_READ_E2E_SEQUENTIAL_SECOND_READ_PASS/);
  assert.match(acceptance, /22222222-2222-4222-8222-222222222222/);
  assert.match(acceptance, /second_payload_source/);
  assert.match(acceptance, /inside2\.bin/);
  assert.match(fixture, /fedcba9876543210fedcba9876543210/);
  assert.match(acceptance, /read-root-two/);
  assert.match(acceptance, /T011_ISSUER_READ_E2E_UNAPPROVED_ROOT_REF_DENIED/);
  assert.match(acceptance, /assert\.deepEqual\(unknownRootReply, \{ version: 1, status: 'denied' \}\)/);
  assert.match(fixture, /PolicyBytesStore/);
  assert.match(fixture, /replay_claims/);
  // Restart the disposable issuer and reuse the same authenticated request
  // identity. A durable claim must deny replay without reissuing file bytes.
  assert.match(acceptance, /T011_ISSUER_READ_E2E_REPLAY_REJECTED_AFTER_RESTART/);
  assert.match(acceptance, /assert\.deepEqual\(replay, \{ version: 1, status: 'denied' \}\)/);
  assert.match(acceptance, /systemctl stop jdc-authority\.service/);
  assert.match(acceptance, /REPLAY_LEDGER_UNCHANGED/);

  const productionMain = await readFile('native/authority-service/src/main.rs', 'utf8');
  assert.match(productionMain, /eprintln!\("E_POLICY_UNAVAILABLE"\)/);
  assert.doesNotMatch(productionMain, /dispatch_one_inherited_read_reply/);
});
