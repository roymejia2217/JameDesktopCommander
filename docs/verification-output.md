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

### GitHub Actions timing evidence (2026-10-16)

GitHub's native workflow-job step timestamps (1-second resolution) and
the Node test runner's final duration provide a cross-checkable baseline:

| Run / revision | Required CI verification step | Node unit duration | Result |
| --- | ---: | ---: | --- |
| 38907268197 / pre-#108 main | 200 s | 192.60 s | 317 pass, 1 skip |
| 38921263253 / #108 PR | 192 s | 183.83 s | 322 pass, 1 skip |
| 38923899432 / postmerge main | 194 s | 185.95 s | 322 pass, 1 skip |

In the last run, the entire `Required CI` job lasted 227 seconds,
including 194 seconds for `Run repository verification`. The 8.05-second
difference between this verification step and the Node duration includes
build and other repository checks; it is **not** a measured MCP delay.
Runs have different test counts and runner conditions; they do not
establish a speedup. MCP transport, model-side read and UI rendering
timings remain separately unmeasured. Each run is publicly inspectable
at `https://github.com/roymejia2217/JameDesktopCommander/actions/runs/<id>`.

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
  Skipped tests are similarly visible by name in the bounded
  `skippedNames` array, with `omittedSkippedNames` for overflow;
  native skip counters and process exit status remain authoritative.
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

## Server handler versus local MCP round-trip timing

`read_process_output(verbose_timing: true)` retains the legacy `Timing:`
field, now measured with Node's monotonic `performance.now()` clock and
labeled **server handler; excludes MCP transport/UI**. The same
opt-in response names its native event-wait outcome: `exit`, `output`,
`timeout` or `not_waited`. Cancelled reads return errors rather than
normal timing evidence. A deadline does not imply the process was
terminated. Process runtime, when available, remains a distinct value.

The official MCP SDK's existing isolated `stdio` integration contract
now records a single monotonic caller-side `LOCAL_STDIO_TIMING` sample
containing `serverHandlerMs` and `sdkStdioRoundTripMs`. The sample
uses an ephemeral child MCP server and a short-lived fixture; it
checks actual completion, PID-bound response and handler duration.
Its caller-side duration includes the local SDK and stdio transport,
serialization and scheduling. **Do not** call the difference network
latency, nor extrapolate this to ChatGPT, Tailscale, remote device
routing or browser rendering. No sensitive parameters, outputs, file
paths, token material or device identities are included in the
published measurement record.

`verbose_timing` remains opt-in. Invalid requests and cancellations
keep existing fail-closed behavior and are **not** reclassified as
successful timed responses. Event-driven waiting, explicit wait
ceilings, retention and one-call tail access remain unchanged.
The next phase requires independently measured real remote tool
receipt/acknowledgment and UI presentation timestamps with a
reviewed privacy policy before any end-to-end latency attribution.

## Guardrails, regressions and limitations

Synthetic fixtures verify success and deliberate failure using real
`node --test` child processes: a failing test exits 1, names remain
present, and diagnostic stack/output is retained exclusively in the
full spec log. The fixture removes the parent's inherited test-runner
context before launching the child; this is test isolation, not a
production override.

The full production test gate remains mandatory. GitHub CI must prove
that Node 22.19 and 24 honor the same dual-reporter configuration,
intentional platform-specific skips are counted and named (never
silently dropped), the log path can be created, and all required
check results remain unchanged.

This is an incremental output-volume improvement, **not** a verified
runtime-duration reduction, completed performance audit or completion
of issue #34. Residual work: instrument subprocess-versus-transport
latency, validate a bounded end-to-end multi-stage gate summary and
exercise Android/Chrome presentation without heavyweight widget loads.
