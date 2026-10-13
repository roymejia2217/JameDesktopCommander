# CP-71 — Squash commit metadata governance incident

**Date:** 2026-10-13
**Affected change:** T011-C4n / pull request #71
**Protected main commit:** `a7f15d7ba3d1c8ddf3f8ccdc95f9fd2e72e5524a`
**CI evidence:** https://github.com/roymejia2217/JameDesktopCommander/actions/runs/38447118743

## Observed outcome

The PR checks succeeded, including real Windows SCM DACL adversarial acceptance,
native Linux, CodeQL and portable candidates. The protected-branch push then failed
the `Required CI` job, at `Validate protected-branch commit`. Commitlint returned
`body-max-line-length`: at least one squash-commit body line exceeded 100 characters.
The failure is deterministic; rerunning the same unchanged commit cannot fix it.

This is a **governance failure**, not evidence that C4n's security tests failed.
Neither a green PR gate nor a signed commit proves postmerge acceptance. The original
failing workflow and commit must remain visible in GitHub's audit history.

## Root cause and missed boundary

The merge caller supplied a custom `commit_message` when invoking GitHub's squash
merge API. That overrode the repository's configured blank squash commit body.
The prospective PR checks validate the title and verify repository defaults, but
cannot examine an API override supplied **after** those checks have completed.

The existing `CONTRIBUTING.md` contract already prohibited manual overrides.
Its violation, rather than an absent Commitlint rule, caused this incident.

## Required merge procedure (fail-closed)

1. Verify the PR head SHA, current protected `main`, review threads and all gates.
2. Require squash as the merge method and pass the **expected head SHA**.
3. **Omit both `commit_title` and `commit_message`** from any merge API request.
   Allow the reviewed PR title and configured `BLANK` body to define the commit.
4. Inspect the resulting `main` SHA, parent, signature and required postmerge checks.
5. On a pending or failed postmerge gate, stop. Never advance to the next T011 stage.

Do not force-push, amend protected history, suppress Commitlint, revise acceptance
criteria, or rerun deterministic failures as a substitute for a correction.

## Recovery and residual exposure

Recover with a legitimate, focused PR using the repository's normal merge defaults.
Retain the original failure, verify the new merge commit independently, and close
this incident only after the new protected-branch `Required CI` passes.

GitHub's repository default settings and PR checks do **not** prohibit a sufficiently
authorized merge caller from explicitly overriding its squash message. The project
cannot claim full premerge enforcement against such API calls through its current CI.
Provider-enforced commit-metadata rules may offer an additional boundary, subject
to repository plan, privileges, and an independently reviewed ruleset change.

T011 remains **non-release / deny-only**. This governance recovery does not authorize
filesystem operations, installed-runtime changes, or C4o before postmerge acceptance.
