# CI verification conventions

This repository uses GitHub Actions for build, test, security, packaging, and
release verification. Workflows are selected by their **product responsibility**,
not by a ticket, date, developer prompt, or one-off incident.

## Naming contract

- **Workflow:** stable subsystem or activity; examples: `CI`, `Native Security
  Tests`, `Distribution Acceptance`, `Native UI Tests`. A filename may retain
  its historical spelling while references are migrated; display names should
  not convey a result that has not been demonstrated.
- **Job:** coherent verification responsibility and platform matrix. Changing a
  job name can change its GitHub required-check context; review branch protection
  and workflow dependencies before doing so.
- **Step:** imperative tool/action plus subject: `Build`, `Test`, `Lint`,
  `Verify`, `Package`, `Upload`. Avoid narratives, dates, issue numbers, and
  "prove" language that overstates the scope of a fixture.
- **Stable step ID:** where tests or workflow outputs depend on a step, use a
  unique native GitHub Actions `id`, not an assertion on human-facing `name`.
  Contract tests must also verify the *actual executable command*, platform
  condition, and required ordering; presence of an ID alone is not evidence.
- **Test case:** name the observable invariant and expected outcome using the
  framework's native test facility. Keep negative cases that detect a regression.
  A scenario name does not convert an isolated fixture into production authority.

## Protected checks

The protected-branch contexts are maintained in
`.github/rulesets/main-protection.json` and verified by
`test/test-main-ruleset-protection.js`:

- `Required CI`
- `PR Governance`
- `CodeQL Security (rust)`
- `CodeQL Security (actions)`

These job names remain unchanged. Never rename or remove a required context
without a separately reviewed ruleset migration that establishes the new context
and verifies it on actual pull requests. Renaming a workflow is not equivalent
to migrating required job contexts.

## Execution ownership

| Workflow | Responsibility | Release implication |
| --- | --- | --- |
| `ci.yml` | TypeScript build, Node compatibility, static checks, runtime tests, MCP contract, and governance integration | Required checks only; no release authorization |
| `codeql.yml` | CodeQL security scanning | Required for Rust and Actions; not a product security guarantee |
| `pr-governance.yml` | PR title, issue closure and protected commit policy | Required governance |
| `codespell.yml` | Spelling | Advisory quality gate |
| `t011-capability-feasibility.yml` | Native security experiments and OS process acceptance on Windows/Linux | Non-shipping evidence, not a grant to enable native authority |
| `distribution-candidate.yml` | Portable archive build, byte provenance, real MCP acceptance and installer tests | Unpublished CI artifacts, not a release |
| `native-operator-ui.yml` | Native UI build, checks, and tests | Non-release build |
| `linux-operator-ui-bundle.yml`, `windows-operator-ui-bundle.yml` | Callable UI bundle builders | Referenced only by distribution acceptance |
| `release.yml` | Release Please with independent release-readiness denial | Release gated by security eligibility |

The native runtime authorization issues #124, #139, and #148 are independent
release blockers. Passing an experimental acceptance workflow does not
satisfy them. Keep `releaseEligible:false` until separately verified.

## Standard tooling and evidence

Prefer each ecosystem's maintained tools and test runners:
`node:test` and the MCP SDK, `cargo test`/`cargo fmt`/`clippy`,
PowerShell's parser and PSScriptAnalyzer, ShellCheck, actionlint, CodeQL,
`npm audit`, and the installed package's real installer lifecycle.
Do not add generic "test everything" wrappers, synthetic pass markers,
or scripts that suppress tool exit codes.

Each gate must have a clear test command, stable platform requirement, explicit
failure status and independent evidence. `skipped` means *not exercised on
this platform*, not PASS. If an integration or production authority fixture is
non-shipping, keep that classification in the job's documented scope.

The current `test:unit` command uses Node's documented custom reporter API
to emit a bounded summary and a full spec log. This is an existing reporter,
not a production test framework. Migrating to interoperable JUnit XML and
artifact retention is a **separate change** requiring a privacy review and
equivalent failure diagnostics on Node 22.19 and Node 24. Do not remove the
reporter or alter its exit-status contract solely for cosmetic consistency.

## Change-control checklist

1. Inventory required checks, job dependencies, matrix variants, and steps
   referenced by tests or output expressions.
2. Demonstrate a RED contract test when a behavioral dependency is wrong;
   for display-only names, compare parsed workflows excluding `name` and
   newly assigned step `id` fields, and retain original commands and guards.
3. Run existing targeted tests, typechecking, actionlint, and official
   repository checks. Require real Windows/Linux CI for OS-specific steps.
4. Accept and merge only an exact verified PR head through protected GitHub
   controls. Never count a running, failed, or skipped gate as successful.
