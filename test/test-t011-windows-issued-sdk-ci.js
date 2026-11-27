import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import YAML from 'yaml';

test('Windows native security CI executes the issued MCP SDK custody proof', () => {
  const workflow = YAML.parse(readFileSync('.github/workflows/t011-capability-feasibility.yml', 'utf8'),
    { uniqueKeys: true });
  const steps = workflow.jobs['native-probe'].steps;
  const index = (id) => steps.findIndex((step) => step.id === id);
  const native = index('windows_issued_sdk_native_read');
  const installed = index('issued_sdk_dependencies');
  const built = index('issued_sdk_runtime');
  const node = steps.findIndex((step) => step.name === 'Use official Node 24');
  const earlyNode = steps.findIndex((step) => step.name === 'Use pinned Node 24 for disposable issuer-to-MCP-SDK proof');
  const linuxStorage = steps.findIndex((step) => step.name === 'Test Linux storage isolation and outside-object integrity');
  const windowsStorage = steps.findIndex((step) => step.name === 'Test Windows storage isolation and outside-object integrity');
  assert.ok(earlyNode >= 0 && installed > earlyNode && built > installed &&
    linuxStorage > built && windowsStorage > built && node > windowsStorage && native > node,
    'both hosted storage proofs require a locked, compiled runtime before acceptance');
  for (const i of [earlyNode, installed, built]) {
    assert.equal(steps[i].if, undefined, 'runtime preparation must execute on both matrix platforms');
  }
  assert.equal(steps[earlyNode].with['node-version'], 24);
  assert.equal(steps[built].run, 'npm run build');
  assert.equal(steps.filter((step) => /npm ci --ignore-scripts --no-audit --no-fund/.test(step.run ?? '')).length, 1,
    'install the locked runtime once before both proofs');
  const linuxMutation = index('linux_issued_sdk_local_mutations');
  assert.ok(linuxMutation > built && linuxMutation < linuxStorage,
    'real local Linux SDK mutation and cancellation proofs must precede hosted acceptance');
  assert.equal(steps[linuxMutation].if, "matrix.target == 'linux-x64'");
  assert.match(steps[linuxMutation].run, /JDC_T011_NODE/);
  for (const [name, marker] of [
    ['local_real_jdc_sdk_to_journaled_native_mutations', 'T011_LINUX_LOCAL_SDK_NATIVE_JOURNAL_EXACT_BYTES_PASS_NONRELEASE'],
    ['local_real_sdk_cancelled_staged_mutation_never_publishes', 'T011_LINUX_NATIVE_JOURNAL_CANCELLED_STAGED_SDK_MUTATION_PASS_NONRELEASE'],
  ]) {
    assert.ok(steps[linuxMutation].run.includes('journaled_mutations::tests::' + name));
    assert.ok(steps[linuxMutation].run.includes(marker));
  }
  assert.match(steps[linuxMutation].run, /--ignored --exact --nocapture/g);
  const inheritedMutation = index('windows_issuer_connected_sdk_local_mutations');
  assert.ok(inheritedMutation > built && inheritedMutation < windowsStorage,
    'real inherited channel must execute before hosted storage acceptance');
  assert.equal(steps[inheritedMutation].if, "matrix.target == 'win32-x64'");
  assert.match(steps[inheritedMutation].run, /JDC_T011_NODE/);
  assert.match(steps[inheritedMutation].run, /journaled_mutations::tests::local_windows_real_sdk_issuer_connected_mutation_channel/);
  assert.match(steps[inheritedMutation].run, /--ignored --exact --nocapture/);
  assert.match(steps[inheritedMutation].run, /T011_WINDOWS_LOCAL_ISSUER_CONNECTED_SDK_MUTATIONS_PASS_NONRELEASE/);
  const serviceHandoff = index('windows_issuer_connected_sdk_separate_service');
  assert.ok(serviceHandoff > inheritedMutation && serviceHandoff < windowsStorage,
    'separate native service handoff must execute before hosted storage acceptance');
  assert.equal(steps[serviceHandoff].if, "matrix.target == 'win32-x64'");
  assert.match(steps[serviceHandoff].run, /JDC_T011_NODE/);
  assert.match(steps[serviceHandoff].run, /journaled_mutations::tests::local_windows_issuer_hands_channel_to_separate_native_service/);
  assert.match(steps[serviceHandoff].run, /--ignored --exact --nocapture/);
  assert.match(steps[serviceHandoff].run, /T011_WINDOWS_SEPARATE_NATIVE_SERVICE_SDK_MUTATIONS_PASS_NONRELEASE/);
  assert.equal(steps[native].if, "matrix.target == 'win32-x64'");
  assert.match(steps[installed].run, /npm ci --ignore-scripts --no-audit --no-fund/);
  assert.match(steps[native].run, /JDC_T011_NODE_BINARY/);
  assert.match(steps[native].run, /--test windows_guarded_client_pipe/);
  assert.match(steps[native].run,
    /protected_issued_sdk_read_preserves_exact_bytes_and_rejects_same_sid/);
  assert.match(steps[native].run, /--ignored --exact --nocapture/);
});

test('hosted Linux requires root-issued SDK cancellation on the same admitted journal before PASS', () => {
  const script = readFileSync('test/security/t011-linux-storage-domain-acceptance.sh', 'utf8');
  const positive = script.indexOf('T011_LINUX_ROOT_ISSUED_REAL_JDC_JOURNALED_MUTATIONS_PASS_NONRELEASE');
  const cancellation = script.indexOf('journaled_mutations::tests::hosted_root_issued_sdk_cancelled_staged_mutation_never_publishes');
  const final = script.indexOf("echo 'T011_STORAGE_LINUX_DOMAIN_PASS_NONRELEASE'");
  assert.ok(positive >= 0 && cancellation > positive && final > cancellation);
  for (const marker of [
    'T011_LINUX_ROOT_ISSUED_SDK_CANCELLED_BEFORE_COMMIT_PASS_NONRELEASE',
    'T011_LINUX_ADMITTED_JOURNAL_CANCELLED_STAGED_SDK_MUTATION_PASS_NONRELEASE',
  ]) {
    assert.ok(script.includes('grep -Fxq ' + marker), 'actual independent client and journal verdict required');
    assert.ok(script.indexOf('grep -Fxq ' + marker) < final);
  }
  assert.match(script, /issue-sdk-cancel/);
  assert.match(script, /test ! -e "\$isolated\/cancelled\.txt"/);
});

test('hosted NTFS active owner rejects real incoming and outgoing mounts before readmission', () => {
  const script = readFileSync('test/security/t011-windows-storage-domain-acceptance.ps1', 'utf8');
  const incoming = script.indexOf("Invoke-ActiveAdmissionAliasProbe $volumeGuid 'mount-paths-not-exclusive'");
  const outgoing = script.indexOf("Invoke-ActiveAdmissionAliasProbe $outerVolumeGuid 'nested-mount-present'");
  const marker = script.indexOf("Write-Output 'T011_WINDOWS_ACTIVE_NESTED_MOUNT_DENIED_NONRELEASE'");
  const restored = script.indexOf("Invoke-AdmissionProbe 'journaled_mutations::tests::hosted_verified_volume_readmits_after_alias_removed'");
  assert.ok(incoming >= 0 && outgoing > incoming && marker > outgoing && restored > marker);
  assert.match(script, /\$errors\.Result[\s\S]*?T011_WINDOWS_VOLUME_ADMISSION_DENIED check=/);
  assert.match(script, /\$admissionAlias = \(Join-Path \$volume '\.jdc-nested-mount'\)/);
  assert.match(script, /E_STORAGE_NESTED_MOUNT_REJECT_CHANGED_DB/);
});

test('hosted NTFS mount transitions verify partition ownership and preserve the primary failure', () => {
  const script = readFileSync('test/security/t011-windows-storage-domain-acceptance.ps1', 'utf8');
  assert.doesNotMatch(script, /Start-Process -FilePath mountvol\.exe/);
  assert.match(script, /Add-PartitionAccessPath -DiskNumber \$partition\.DiskNumber -PartitionNumber \$partition\.PartitionNumber/);
  assert.match(script, /Remove-PartitionAccessPath -DiskNumber \$partition\.DiskNumber -PartitionNumber \$partition\.PartitionNumber/);
  assert.match(script, /E_STORAGE_ALIAS_TARGET_MISMATCH/);
  assert.match(script, /E_STORAGE_ALIAS_UNPROVEN_REPARSE/);
  assert.match(script, /\$primaryFailure = \$null/);
  assert.match(script, /catch \{\s+\$primaryFailure =/);
  assert.match(script, /if \(\$null -ne \$primaryFailure\) \{ throw \$primaryFailure \}/);
  assert.match(script, /E_STORAGE_CLEANUP_FAILED_/);
});

test('hosted NTFS acceptance verifies all dedicated primary tokens and denies absent issuer privileges', () => {
  const script = readFileSync('test/security/t011-windows-storage-domain-acceptance.ps1', 'utf8');
  const preflight = script.indexOf("Invoke-AdmissionProbe 'windows_token::fixture_tests::hosted_fixture_issuer_launch_prerequisites'");
  assert.ok(preflight >= 0, 'actual issuer preflight must execute, not just compile');
  for (const [role, variable] of [['SERVICE', 'service'], ['CLIENT', 'client'], ['ATTACKER', 'attacker']]) {
    const call = "Invoke-AdmissionProbe 'windows_token::fixture_tests::hosted_fixture_principal_matches_expected_role' 'T011_WINDOWS_FIXTURE_" + role + "_TOKEN_PASS_NONRELEASE' $" + variable + ".Credential";
    assert.ok(script.includes(call), 'actual separate process required for ' + role);
    assert.ok(script.indexOf(call) < preflight, 'role observation precedes issuer capability verdict');
  }
  assert.match(script, /Invoke-AdmissionProbe 'windows_token::fixture_tests::hosted_fixture_issuer_launch_prerequisites' 'T011_WINDOWS_DISTINCT_ISSUER_PREREQUISITES_PASS_NONRELEASE' \$null/);
  assert.match(script, /fixture-principal-input\.txt/);
});
