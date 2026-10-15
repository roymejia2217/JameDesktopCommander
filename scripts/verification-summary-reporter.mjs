// Node's documented test reporter API: one compact console summary.
// Full, unmodified spec output is emitted by Node's second native reporter.
const MAX_FAILURE_NAMES = 20;
const DEFAULT_LOG = '.tmp/verification/unit-spec.log';

export default async function* verificationSummary(source) {
  const failedNames = [];
  let totalFailures = 0;
  let summary;
  for await (const event of source) {
    if (event.type === 'test:fail') {
      totalFailures += 1;
      if (failedNames.length < MAX_FAILURE_NAMES) {
        failedNames.push(String(event.data?.name ?? 'Unnamed test failure'));
      }
    } else if (event.type === 'test:summary') {
      // Node also emits per-file summaries in isolated mode; the final
      // cumulative summary is last, and owns the authoritative test totals.
      summary = event.data;
    }
  }
  const valid = summary?.counts && Number.isFinite(summary.duration_ms);
  const ok = valid && summary.success === true &&
    summary.counts.failed === 0 && summary.counts.cancelled === 0;
  const report = {
    status: ok ? 'PASS' : 'FAIL',
    exitCode: ok ? 0 : 1,
    counts: valid ? {
      tests: summary.counts.tests,
      passed: summary.counts.passed,
      failed: summary.counts.failed,
      cancelled: summary.counts.cancelled,
      skipped: summary.counts.skipped,
      todo: summary.counts.todo,
    } : null,
    durationMs: valid ? summary.duration_ms : null,
    failureNames: failedNames,
    omittedFailureNames: Math.max(0, totalFailures - failedNames.length),
    fullLog: process.env.JDC_VERIFICATION_LOG_PATH || DEFAULT_LOG,
  };
  yield 'VERIFICATION_SUMMARY ' + JSON.stringify(report) + '\n';
}
