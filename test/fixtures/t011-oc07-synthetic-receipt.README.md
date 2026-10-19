# OC-07.2h synthetic receipt parser fixture

**Scope:** Test-only, non-release. This is an *unapproved wire-format
hypothesis*, not a production protocol, token serializer, collector,
cryptographic implementation or an SCM IPC channel.

This zero-dependency Node fixture exercises offline rejection properties
requested by [OC-07.2h](../../docs/security/T011-C4O-OC072H-SECURITY-DESIGN-REVIEW.md):
one exact framed JSON message, bounded length and lifetime, unsupported
fields/versions, bad encoding, provenance-marker mismatch and replay.
The test verifier must also receive the exact **expected run attempt** and
**previously issued 32-byte challenge**, rejecting validly encoded but
different values before consuming the challenge. Missing or malformed
verifier expectations are denial, not an implicit wildcard.
No Windows token, SID, privilege name, actual service account, private
key, signature, network, filesystem or OS authorization information is
processed. All identifiers and fingerprints used in tests are synthetic.

The fixture's `expected` fields are **caller-supplied** and MUST NOT be
regarded as independently authenticated evidence. Its replay `Set`
is local to the test process and is NOT durable, crash safe, authenticated
or suitable for a security boundary. Neither canonical serialization nor
the apparent fingerprint verifies recipient custody, SCM identity,
binary provenance or the GitHub runner's trust.

The code deliberately lives under `test/fixtures` and is imported
only by `test/test-t011-oc07-synthetic-receipt.js`. It is not used by
any runtime or enabled service. The synthetic `schemaVersion: 0` has no
production compatibility promise.

**Acceptance:** Native Windows SCM continues to terminate deny-only;
`releaseEligible: false`; real-token export and OC-07.3 remain blocked
until independent human approvals, secure recipient custody, verified
provenance and the adversarial Windows/crypto gates are complete.
