# Runtime build provenance for `get_config`

The production `npm run build` embeds a strict metadata record in
`dist/build-provenance.json`. Its `sourceCommit` is the source checkout's
Git HEAD and `workspaceClean` is the state of tracked/untracked source
files observed when the build completed. The record intentionally excludes
usernames, local paths, URLs, profiles, command lines and credentials.

`get_config` reports the record as `structuredContent.runtimeBuild`,
separate from the user-editable `config` data and includes a short text
summary for clients that do not read structured content. This is **not a
cryptographic attestation** of binary/runtime identity and cannot prove
that a particular deployed instance is the source of a tunnel response.

No `.git` directory means `kind: unavailable`, not a fabricated SHA.
Modified builds carry `workspaceClean: false` and must not satisfy
stable-release eligibility. A release acceptance gate must compare the
embedded commit and package version with the hashed candidate manifest,
GitHub source revision and deployed artifact. The existing manifest remains
`releaseEligible: false` until separate release, security and rollback
gates are satisfied.

The old `get_config` stderr full-configuration dump is removed because
logs must not duplicate arbitrary configuration values. No task/service
restart or installed runtime mutation is part of this change.
