# T011 C4o / OC-07.2g — Confidential SCM receipt protocol: design gate

**Decision:** PROPOSED, NOT APPROVED. Design-only; no executable collector.
**Tracking:** [OC-07 issue #80](https://github.com/roymejia2217/JameDesktopCommander/issues/80).
**Boundary:** Windows SCM remains terminal `Stopped`, deny-only, `releaseEligible: false`.

## Purpose and authority

The published repository, Actions logs, uploaded artifacts and job summaries
are **not** confidential destinations. The real Windows SCM token produced
`PrivilegeBaselineUnreviewed`, but its enabled privilege-name inventory
and all group attributes have not received independent review. Do not
approve a guessed or runner-derived privilege allowlist.

OC-07.2a–d retain privately owned token observations in SCM process RAM.
OC-07.2e/f cover the two existing direct official artifact-upload
configurations but do not secure arbitrary logs, third-party actions,
binary archives or other outbound channels. This record defines gates;
it does **not** authorize any exporter or evidence release.

## Trust boundaries and residual threats

1. **Origin:** an ephemeral, genuine SCM-launched
   `JameDesktopCommanderAuthority` instance executing a reviewed binary
   under its actual Windows virtual service SID. The runner user token,
   supplied SID string, environment variable or CLI invocation does
   not establish the SCM identity.
2. **Collector:** a reviewed, separately identified process that receives
   at most one bounded receipt. It must verify the kernel-issued SCM
   process identity and exact service instance. The service must
   independently validate the authorized collector and endpoint.
3. **Recipient:** a public encryption key authenticated independently
   of CI, with its private decryption key held offline by an accountable
   reviewer. A key supplied by a PR or generated with its private
   counterpart in CI is not trusted.
4. **Host:** an ephemeral protected-main Windows runner is mandatory,
   but it remains inside the provider/administrator trust boundary.
   Privileged runner compromise or provider access may reveal process
   memory before encryption. Recipient encryption does not address
   those risks. Explicit residual-risk acceptance is required.

GitHub flags, workflow metadata, job labels, a pipe pathname, encrypted
bytes or process names alone are not cryptographic attestations.

## Independent approvals required before any exporter implementation

- **Recipient custody:** independently authenticated public recipient,
  owner, offline private-key custody, key rotation/revocation, documented
  fingerprint/provenance and explicit reviewer authorization.
- **Cryptography:** evaluate a maintained, standard `age` implementation,
  with pinned reviewed version, binary provenance and repeatable fixture
  decrypt/negative tests. Use the standard authenticated encryption
  implementation; never invent custom cryptographic algorithms.
  Encryption authenticates ciphertext integrity but does not, by itself,
  prove who originally produced the plaintext.
- **Build and service:** signed protected-main source/commit/tree,
  locked dependencies, compiler version, verified SCM registration,
  service DACL and virtual/restricted SID, service binary digest and
  separately verified collector binary digest. Do not trust PATH or
  user-supplied build labels.
- **Mutual endpoint verification:** review the precise Windows
  supported-IPC API calls and limitations before coding. Named-pipe
  service/client ACLs plus live kernel token checks must resist
  squatting, impersonation, PID reuse, remote clients, inherited
  handles, arbitrary endpoints and service restart races.
- **Confidentiality:** bound all plaintext data in process memory
  without file, console, exception, summary, ordinary artifact, cache,
  debugger or log disclosure. Encrypt successfully before any
  transferable output is created; forbid reversible/token dictionary
  hashes, partial plaintext fallbacks and recovery dumps.
- **Retention and custody:** one receipt per reviewed run, bounded
  time and size, ciphertext storage at most 24 hours, explicit
  cancellation, cryptographic ownership and verifiable cleanup;
  cleanup failures are incidents, not an accepted CI pass.

No approved offline recipient, recipient-toolchain assurance,
authenticated transport or residual runner-risk acceptance is recorded
in this repo. **Export-capable implementation remains blocked.**

## Proposed encrypted envelope and provenance

An eventual versioned, length-bounded canonical envelope would contain:

- Protected repository/commit/tree and verified commit signing, runner
  workflow job/run/attempt and source/toolchain provenance.
- Service and collector executable hashes; exact SCM config, SID,
  restricted SID state, live service instance and OS build/architecture.
- From one verified SCM kernel token handle: TokenUser, primary and
  restricted group SID attributes, integrity label, all validated
  privileges (enabled and disabled, with names/flags) and classification.
- A fresh unpredictable single-use challenge, recipient version,
  schema version, observation sequence and terminal receipt status.

Provenance must be independently verified from protected code, Windows
SCM, live process handles and approved recipient information; a
self-asserted JSON field does not establish identity. No plaintext
receipt content or reversible privilege fingerprints may appear in a
public manifest. Ciphertext checksums alone do not prove origin.

## Proposed state transitions — NOT IMPLEMENTED

`Disabled` is currently the **only** legal state. The following
transitions are solely design candidates, subject to approvals:

`Preflight -> Authenticated -> Observed -> Encrypted -> Staged -> Cleaned`

- **Preflight:** protected-main signature/build, immutable provenance,
  authorized independent recipient, reviewed collector and isolated
  Windows runner validation all pass. Unavailable means deny.
- **Authenticated:** confirm both live endpoint identities by documented
  kernel evidence before transferring one fresh challenge-bound
  message. Reject caller-selected pipe or file destinations.
- **Observed:** use precisely the SCM-owned kernel process token,
  enforcing bounded native SID/group/privilege decoding and identity.
- **Encrypted:** include instance provenance and challenge inside one
  authenticated ciphertext envelope. Keep plaintext solely in memory.
- **Staged:** publish only verified ciphertext to an independently
  approved, short-lived destination. Changing the current two-upload
  allowlist requires a separately governed review and PR.
- **Cleaned:** confirm stopped service state, closed handles, no
  plaintext residuals and expected cleanup. Do not accept failures.

Every error results in a categorical, non-sensitive denial while
preserving `releaseEligible: false` and SCM terminal `Stopped`.
No state grants filesystem I/O or enters `Running`.

## Mandatory adversarial acceptance before activation

- Forged client/server SID and service instance, mismatched token
  identity, endpoint squatting, impersonation and recycled PIDs.
- Separate low-privilege attacker attempting pipe read, write, replace,
  remote connection, replay, concurrent session or inherited-handle use.
- Malformed, partial, excessive or duplicated native token entries,
  privilege resolution failures and inconsistent group attributes.
- Key/recipient substitution, revoked key, tampered ciphertext,
  missing/invalid format and unavailable approved crypto runtime.
- Incorrect commit/tree, unsigned or swapped collector/service image,
  changed OS build, spoofed runner flags, untrusted PR invocation.
- Interruption before encryption, stderr/log/dump plaintext disclosure,
  broadened artifact paths, cancellation and retention failures.
- Failed cleanup of files, handles, service registration, attacker
  fixtures or ciphertext copies; nonzero exit alone is not proof.

Run the security acceptance under an **actual ephemeral Windows SCM
virtual-account token** plus an independently provisioned attacker.
Assert specific failure codes, no unintended privilege grant and
terminal SCM denial without printing token details in public CI.
A separate human reviewer must decrypt and accept real evidence
before the independent OC-07.3 privilege-baseline decision.

## Decision and remaining blockers

This ADR does **not** choose or approve a concrete recipient, crypto
distribution, IPC mechanism, trusted collector implementation or host
trust-risk exception. It is a design specification, not a production
readiness claim. The next executable work must wait for the named
approval owners and independently testable acceptance criteria.

OC-07 issue #80 stays **OPEN**. Protected policy custody, authenticated
operational IPC/revocation, native C5 filesystem I/O, adversarial
D and production release E remain blocked.
