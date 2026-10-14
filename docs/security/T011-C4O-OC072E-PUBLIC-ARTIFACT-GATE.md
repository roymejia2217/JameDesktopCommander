# T011 C4o / OC-07.2e — Public CI artifact path governance

**Status:** isolated non-release guard; acceptance requires protected PR and postmerge.
**Tracking:** [OC-07 issue #80](https://github.com/roymejia2217/JameDesktopCommander/issues/80).
**Service:** permanently deny-only (`Stopped`, `releaseEligible: false`).

## Threat boundary

The repository is public. GitHub Actions logs, job summaries and ordinary
uploaded artifacts are not confidential destinations. The T011 native
feasibility workflow currently publishes only the pinned native capability
probe binary and its committed Cargo lockfile, never the Windows SCM service
binary or private process-token evidence.

A broad path, glob, CI expression, extra upload step or increased retention
could accidentally expand the downloadable artifact set. This increment
introduces a versioned, parser-based **test-only CI regression policy**
for the existing `native-probe` workflow. It does not create or configure
an evidence exporter.

## Implemented policy

The `test/test-t011-native-artifact-policy.js` suite parses the committed
`.github/workflows/t011-capability-feasibility.yml` using the existing
`yaml` dependency with unique-key validation. A small pure validator in
`test/security/support` rejects incompatible workflow changes.

The contract requires exactly one SHA-pinned `actions/upload-artifact`
step in `jobs.native-probe.steps`, containing **exactly**:

- `native/capability-probe/Cargo.lock`
- `native/capability-probe/target/release/jdc-capability-probe.node`

No other path is authorized; no glob, expression, exclusion, directory
prefix or SCM evidence file is equivalent. The step must retain an upload
name, `retention-days: 1`, `if-no-files-found: error` and unmodified
read-only workflow `permissions: { contents: read }`.

## Test matrix / fail closed

The test suite proves acceptance of the current allowlist and rejection
of a broadened native directory, an authority service target directory,
a filename glob, an expression-provided path, removed/duplicated uploads,
unpinned upload action, extended retention, permissive missing-file
behavior and elevated workflow permissions. All tests use synthetic
in-memory mutations of the parsed workflow, without installing a service
or writing an artifact.

This is **defense in depth for one existing artifact upload surface**,
not a guarantee against a malicious process printing secrets to logs,
other workflows introducing new uploads, other exfiltration channels,
or tampering with the tests. Repo branch protection, PR review, code
audit, Windows SCM real-token acceptance and CodeQL remain mandatory.
The gate is intentionally narrow to avoid a misleading claim of general
confidentiality.

## Required future OC-07.2 evidence handoff

**No approved encryption recipient or authenticated handoff exists.**
Do not enable any SCM snapshot serialization, output, network transport,
file writes or CI uploads while these controls are absent.

Before designing an active exporter, separately review and approve:

1. A pinned, independently verified offline public encryption recipient,
   with decryption private key held **outside GitHub Actions** and a
   documented rotation/revocation process. Prefer an established format
   such as `age` following dependency and binary provenance review; do
   not introduce bespoke cryptography.
2. An ephemeral, protected-`main`-only Windows SCM service installation,
   exact commit/build/binary hash/service-instance binding, signed
   provenance, OS version/build and evidence schema version. PR workflows,
   environment variables or service-account strings alone are not proof.
3. A reviewed one-time authenticated SCM-to-collector handoff with exact
   service-principal verification, bounded payload sizes and deadline,
   anti-replay challenge, restrictive security descriptor, no
   caller-controlled file or endpoint path, and failure cleanup.
4. Encrypt **before** creating any transferable artifact or emitting
   output. The full privilege names, group SIDs, attributes and process
   identity must not be revealed through plaintext logs, reversible
   fingerprints, dictionary-attackable hashes or exception messages.
5. Prove fail-closed behavior against separate unprivileged principals,
   forged pipes/clients, replay, destination substitution, interrupted
   capture, corrupt ciphertext, revoked recipient, metadata mismatch,
   insufficient ACLs and failed cleanup. Keep retention at or below
   one day, with independent deletion verification.

Only after secure evidence reaches a verified offline reviewer can
OC-07.3 examine the real SCM privilege inventory and propose an
explicit, independently reviewed least-privilege baseline. C5 native
filesystem I/O, protected policy custody, authenticated operational IPC,
adversarial D and release E remain blocked.
