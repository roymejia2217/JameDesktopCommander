# Windows tunnel clean-exit recovery (opt-in)

The native Windows Task Scheduler supports repetition patterns on BootTrigger.
An installation using `tunnel install ... --recover-on-exit` registers a
five-minute repeating boot trigger with `IgnoreNew`. If the process remains
running, new triggers are ignored. If it exited unexpectedly, including exit
code 0, the next trigger may start it again. This uses the **documented native
scheduler**, not a homegrown restart loop or external polling service.

The default installation remains unchanged (boot and RestartOnFailure only).
An existing task is never replaced without explicit `--force`; the
installation's action and service identity are otherwise unchanged.

**Operator intent:** `tunnel stop` disables the task *before* requesting
termination, so repeating triggers cannot reverse an intentional stop.
`tunnel start` enables the task before requesting a new instance.
The external restart worker checks Task Scheduler enabled state before
touching processes and again immediately before requesting start. The
worker's internal recycle functions do **not** enable a disabled task.
Failures in enable/disable are surfaced rather than silently bypassed.

**Limitations / release blockers**

- Task Scheduler cannot revive a hung-but-still-running process under
  `IgnoreNew`. MCP functional health and independently authorized recovery
  remain a separate requirement.
- Repeating triggers are best-effort OS scheduling, not a real-time
  availability SLA. This design does not add process health probes.
- A concurrent operator stop between the final check and task start depends
  on the Scheduler's disabled-task enforcement. Real-host race and ACL tests
  are required before operational deployment.
- The task may have been stopped externally without disabling it; such
  actions are outside the `tunnel stop` operator-intent contract.
- This is not an authorized production deployment. Full packaging, release,
  rollback, native task import, restart races and end-to-end MCP acceptance
  remain required; issue #80's SCM security gate remains deny-only.

References: Microsoft Task Scheduler Repetition (triggerBaseType),
MultipleInstancesPolicy and schtasks /Change /ENABLE|/DISABLE documentation.
