# Windows Task Scheduler real-host clean-exit acceptance

Status: **real-host test passed on an isolated Windows 10 machine, 2026-10-15**.
Not a release gate override, deployed repair, or proof that a BootTrigger fires
after reboot.

## Reproduce (explicit opt-in)

Run `npm run test:windows:task-recurrence:realhost` on a disposable Windows
host, while logged on using an account authorized to register S4U tasks.
This test is **never included in ordinary `npm test` or CI**. It requires
approximately 155 seconds. Node.js 22 and Windows Task Scheduler must be
available. Do not schedule this test alongside a reboot.

The test uses documented Task Scheduler COM interfaces to register one
uniquely named temporary task in a temporary task folder. The task launches
`node.exe` with the isolated `test/fixtures/task-clean-exit.mjs` fixture.
That fixture writes only the constant `exit-zero` into a private local
receipt file and terminates with code 0. No network use, product task, tool
invocation, or credential is required.

The temporary **time-based trigger** starts after ten seconds and repeats
every minute with `IgnoreNew` and an S4U principal. After a fixed 85-second
wait, the test requires exactly two fixture executions. It then disables
the task using native `schtasks /Change /DISABLE`, waits past the third
scheduled firing, and requires the execution count to remain unchanged.
The test always attempts to remove its unique task, folder, and private
receipt directory; separate post-run inspection must confirm zero leftovers.

### Observed result

- Native S4U task registered: PASS
- `PT1M` recurrence and `IgnoreNew`: PASS
- Two invocations ending in code 0: PASS
- Intentional disable stopped subsequent invocations: PASS
- Remaining temporary Task Scheduler tasks/folders: 0
- Production Windows Tunnel task remained running

This proves native repeating-task execution and stop preservation with a
time trigger. Earlier tests also verified native acceptance of the XML
`BootTrigger` repetition syntax. **It does not prove a real boot trigger
will fire after reboot**: that requires a disposable-host reboot test.

## Unproven and blocking production rollout

- Reboot/power failure, network loss and reconnect, nonzero child exit,
  locked/busy child, task registration update, concurrent STOP/restart
  races, privilege/ACL denial and rollback.
- `IgnoreNew` prevents a new instance while an existing instance is
  still running. No hung MCP process recovery is demonstrated here.
- Running this test does not authenticate the caller of `tunnel status`,
  authorize operational restart, satisfy SCM issue #80 or permit changing
  installed product tasks.
- A stable release also requires versioned/provenanced artifacts and
  a tested replacement and rollback of the existing installed runtime.

The harness must fail on an unexpected execution count, registration failure,
scheduler policy mismatch, or failure to preserve an intentional stop.
Do not relax those assertions for green status. Review any cleanup warning
and remove only the uniquely named isolated test objects before retrying.
