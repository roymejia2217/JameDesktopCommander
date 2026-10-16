// Node's documented test reporter API: one compact console summary.
// Full, unmodified spec output is emitted by Node's second native reporter.
const MAX_FAILURE_NAMES = 20;
const MAX_FAILURE_DETAIL_CHARS = 320;
const DEFAULT_LOG = '.tmp/verification/unit-spec.log';

// Emit a bounded assertion message only, never raw stacks, stdout, or stderr.
// Tests must not place secrets into assertion messages or test names.
function boundedText(value, maxLength) {
  return typeof value === 'string'
    ? value.replace(/[\x00-\x1f\x7f-\x9f]/g, ' ').slice(0, maxLength)
    : null;
}

export default async function* verificationSummary(source) {
  const failedNames = [];
  const failureDiagnostics = [];
  const skippedNames = [];
  let totalFailures = 0;
  let totalSkips = 0;
  let summary;
  for await (const event of source) {
    if (event.type === 'test:fail') {
      totalFailures += 1;
      if (failedNames.length < MAX_FAILURE_NAMES) {
        const name = boundedText(event.data?.name, 160) ?? 'Unnamed test failure';
        failedNames.push(name);
        failureDiagnostics.push({
          name,
          detail: boundedText(event.data?.details?.error?.message,
            MAX_FAILURE_DETAIL_CHARS),
        });
      }
    } else if (event.type === 'test:pass' &&
      event.data?.skip !== undefined && event.data.skip !== false) {
      totalSkips += 1;
      if (skippedNames.length < MAX_FAILURE_NAMES) {
        skippedNames.push(boundedText(event.data?.name, 160) ??
          'Unnamed skipped test');
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
    failureDiagnostics,
    skippedNames,
    omittedSkippedNames: Math.max(0, totalSkips - skippedNames.length),
    omittedFailureNames: Math.max(0, totalFailures - failedNames.length),
    fullLog: process.env.JDC_VERIFICATION_LOG_PATH || DEFAULT_LOG,
  };
  yield 'VERIFICATION_SUMMARY ' + JSON.stringify(report) + '\n';
}
