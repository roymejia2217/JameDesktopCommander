# T011 / OC-07 — Automated security review boundaries

**Scope:** independent vendor-maintained scanners for an existing,
deny-only security implementation. **Not a privilege authorization.**
**Status:** candidate until governed PR and postmerge checks pass.

## Reviewed automation

- Retain the original, SHA-pinned GitHub CodeQL JavaScript/TypeScript job
  and its existing stable check name.
- Add a separate CodeQL job matrix for Rust and GitHub Actions, using
  GitHub's maintained `security-extended` query suite. Its official
  CodeQL action and checkout action reuse existing commit-pinned SHAs.
- Use GitHub-hosted Ubuntu 24.04 and source-only CodeQL build mode
  `none`, supported for Rust. Analysis results are security alerts;
  there are no ordinary artifact uploads or custom network exporters.
- Apply only `contents: read` and `security-events: write` permissions
  for submitting code-scanning findings. No repository secrets or
  service-account credentials are supplied.
- A native Node test validates matrix coverage, pinned actions, permissions,
  query suite and noninterference with the existing CodeQL check.
## What a scanner can and cannot prove

CodeQL can identify source-level vulnerability patterns, including
insecure data flow, accidental disclosure and CI workflow weaknesses.
It does **not** exercise a live Windows SCM token, demonstrate Windows
named-pipe peer identity, enforce kernel ACLs, establish trustworthy
cryptographic key custody or validate the holder of a secret key.
A successful job is not an independent approval of an enabled privilege
allowlist or a substitute for a genuinely separate security authority.

OC-07.2g/2h keep their unapproved design status. Real-token export,
collector IPC, key handling, encrypted receipts, policy elevation and
production startup remain prohibited until separately authorized and
proved against an ephemeral Windows SCM instance with hostile actors.

## Acceptance / failure treatment

The hosted GitHub Actions run must finish for both additional languages.
Any query, extractor, upload or runner failure is a failed check, not a
reason to suppress it. Security findings are triaged without blanket
suppressions, bypasses or lowering severity thresholds. Follow existing
CodeQL code-scanning branch rules and mandatory governance checks.
The existing cargo-deny, Clippy and native SCM refusal tests remain
authoritative for their separate contracts. Do not use CI `PASS` as
permission to set `releaseEligible: true`.

No installed Windows service, public tunnel or credential is changed.
