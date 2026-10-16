# Verification output: compact console, complete local test logs

**Scope:** incremental work on [issue #34](https://github.com/roymejia2217/JameDesktopCommander/issues/34).
This change affects the display of the existing Node unit-test suite only.
All test files, test selection, concurrency, quality gates, build stages,
Husky checks and exit-code behavior remain unchanged.

## Baseline and what was actually measured

The accepted OC-07.2g isolated Windows worktree ran the unchanged Husky
pre-push gate with 238 passing Node tests. The Node runner reported
217740.7675 ms; the complete push process exited 0 in 245.63 seconds
and retained approximately 2354 output lines. These observations imply
roughly 28 seconds outside the Node test-runner phase, including build,
audit, tool validation, git operations and transport overhead. They do
**not** isolate the MCP transport contribution; no speedup is claimed.

TypeScript already has `listEmittedFiles: false`. Changing that option
again would provide no benefit. The Node test suite's own extensive
stdout/stderr makes the normal terminal transcript expensive to render.

## Standard Node.js reporter composition

The `test:unit` npm command retains the same `test/test*.js` selection,
Node environment setup and `--test-concurrency=1`. It now uses two
reporters through documented Node.js CLI flags:

- `scripts/verification-summary-reporter.mjs` produces a single
  `VERIFICATION_SUMMARY` JSON line on stdout after the runner ends.
  Counts come from Node's native aggregate `test:summary` event;
  failed test names come from `test:fail` events. Up to 20 names are
  shown, and `omittedFailureNames` makes additional failures explicit.
  The same capped set includes `failureDiagnostics`, with at most 320
  characters of the assertion message per failure, flattened to a single
  line; raw stacks and test stdout/stderr are never copied into this
  compact report. Missing messages are represented by `null`.
- Node's built-in `spec` reporter retains the **entire** test output
  at `.tmp/verification/unit-spec.log` in the isolated checkout.
  The file is already excluded by `.gitignore` and is neither pushed
  to Git nor uploaded to GitHub Actions artifacts by this change.

Use the Desktop Commander read_file tool on that log **only when needed**.
The log is ordinary plaintext developer diagnostic output: do not
print secrets in tests, treat it as a confidential evidence channel
or upload it to a public CI artifact. The next run replaces the
previous same-path log, so copy it to an approved location before
re-running only if retention is explicitly authorized.

The final JSON includes PASS/FAIL status, corresponding runner exit
code, pass/fail/skip/cancel/todo counts, measured Node test duration,
failed names, overflow count and full-log location. An absent or
malformed native summary yields FAIL rather than a fabricated PASS.
The real Node process—not the reporter—continues to enforce exit codes;
the reporter never overrides an unsuccessful process to return zero.

## Guardrails, regressions and limitations

Synthetic fixtures verify success and deliberate failure using real
`node --test` child processes: a failing test exits 1, names remain
present, and diagnostic stack/output is retained exclusively in the
full spec log. The fixture removes the parent's inherited test-runner
context before launching the child; this is test isolation, not a
production override.

The full production test gate remains mandatory. GitHub CI must prove
that Node 22.19 and 24 honor the same dual-reporter configuration, no
tests have been skipped, the log path can be created, and all required
check results remain unchanged.

This is an incremental output-volume improvement, **not** a verified
runtime-duration reduction, completed performance audit or completion
of issue #34. Residual work: instrument subprocess-versus-transport
latency, validate a bounded end-to-end multi-stage gate summary and
exercise Android/Chrome presentation without heavyweight widget loads.
