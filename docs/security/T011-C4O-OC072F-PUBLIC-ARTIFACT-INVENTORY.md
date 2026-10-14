# T011 C4o / OC-07.2f — Repository-wide public artifact upload inventory

**Scope:** isolated test-only, non-release security-hardening increment.
**Acceptance:** protected PR plus successful required CI and postmerge.
**Tracking:** [OC-07 issue #80](https://github.com/roymejia2217/JameDesktopCommander/issues/80).
**SCM:** terminal `Stopped`, `releaseEligible: false`, no I/O grant.

## Existing, reviewed GitHub artifact surfaces

The repository is public. GitHub Actions logs and ordinary artifacts do
**not** provide a confidential evidence channel. OC-07.2e protects one
native CI upload, but a separate candidate packaging workflow can also
upload an archive. OC-07.2f inventories all checked-in GitHub workflow
files and refuses additional uses of the official upload-artifact action
without an explicit, independently reviewed policy change.

The two existing upload surfaces are:

1. `t011-capability-feasibility.yml`, job `native-probe`: one upload
   of only the pinned native capability probe and its committed Cargo.lock.
   The existing OC-07.2e validator remains authoritative for this upload:
   `retention-days: 1`, exact path list, SHA-pinned action and read-only
   contents permission.
2. `distribution-candidate.yml`, job `portable-candidate`: one
   SHA-pinned upload of the **single** existing runner temporary archive
   `UNPUBLISHED-jdc-portable-${{ matrix.target }}.tar` with the reviewed
   `runner.temp` directory prefix, `retention-days: 7`,
   `if-no-files-found: error`, and `compression-level: 0`. Workflow
   permissions remain `contents: read`; job-level overrides are denied.

These are historical packaging/probe artifacts, not SCM token receipts.
This increment intentionally does **not** lower an existing seven-day
retention policy without separate distribution-policy review.

## Implementation and tests

`test/test-t011-public-artifact-inventory.js` dynamically enumerates
the `.github/workflows/*.yml` and `*.yaml` files with Node's standard
filesystem library and parses each with the already installed `yaml`
package using `uniqueKeys: true`. The reusable, pure helper
`test/security/support/t011-public-artifact-inventory.js`:

- Calls the stronger OC-07.2e native upload-policy validator unchanged.
- Locates official `actions/upload-artifact` references across every
  parsed job, including newly introduced workflows, and insists that
  exactly the two approved surfaces exist.
- Requires the approved, full action commit SHA, exact artifact name,
  exact portable candidate path, retention, compression, missing-file
  behavior and least-privilege permissions.
- Rejects additional uploads, missing uploads, broad paths, service
  artifact paths, unpinned action refs and unauthorized workflow changes.

TDD RED demonstrated that the temporary permissive validator did not
detect these mutations. TDD GREEN passed **17/17 new inventory tests**
and **17/17 previous OC-07.2e tests**, for 34/34 focused cases.
All tests use in-memory YAML mutations; no host service, tunnel, runtime
or CI artifact is touched. Full local pre-push, protected PR and hosted
postmerge validations remain mandatory for acceptance.

## Explicit limitations and next security gate

This guard detects only direct references to the *official*
`actions/upload-artifact` action in the repository's workflow YAML.
It cannot certify the content of candidate TAR files, discover third-
party or nested reusable workflow uploads, prevent shell/HTTP log-based
exfiltration, or protect against malicious code changes. It is
defense in depth, not evidence confidentiality.

**No independently verified offline encryption recipient** and no
authenticated SCM-to-collector one-time transport have been approved.
Until both exist, do not add any Windows SCM snapshot file writer,
serializer, pipe, transfer, logs or upload. A future capture requires
a standard audited cipher and pinned tooling, verified key custody,
provenance binding to source SHA/build/OS/service token, challenge-based
mutual identity checks, strict ACLs, bounded payload, non-admin and
replay tests, one-day-or-less retention and verified cleanup. Avoid
reversible token hashes and bespoke cryptography.

OC-07.3 cannot approve a least-privilege allowlist before independent
review of confidential real-token evidence. Protected policy custody,
operational authenticated IPC, native C5 filesystem I/O, adversarial
D and production release E remain out of scope and blocked.
