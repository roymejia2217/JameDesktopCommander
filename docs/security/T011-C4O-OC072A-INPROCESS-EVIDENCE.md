# T011 C4o OC-07.2a — Confidential SCM observation boundary

**State:** pre-export engineering slice, subject to protected CI and review.
**Release:** prohibited; `releaseEligible: false`; SCM always terminal `Stopped`.
Tracking: [issue #80](https://github.com/roymejia2217/JameDesktopCommander/issues/80).

## Verified constraints

The repository is **public**. GitHub Actions logs and ordinary uploaded
artifacts are not confidential evidence destinations. OC-07.1 proved that the
real SCM service can classify a kernel-issued token and deny with terminal
code 3, but the public categorical log contains no actual reviewed privilege
names, group SIDs or group attributes.

There is currently **no independently verified offline recipient public key**
or approved encrypted capture protocol. It would be unsafe to publish names,
raw SIDs, reversible fingerprints or a privilege hash: the Windows privilege
name space is small enough for dictionary attacks.

## Implemented boundary

The Windows-only native observer now creates a private,
`VerifiedScmTokenSnapshot` from its **single** kernel-issued process token
handle, after matching `TokenUser` with the configured virtual service SID.
It retains a bounded, validated privilege-name inventory and the same
previously checked token type, restricted-service SID attributes,
elevated-group flag and integrity RID in process memory. No public getter,
`Debug`, serialization, file, pipe, network or logger receives this snapshot.

The existing public observer returns **only** the original
`TokenFinding` category. SCM continues to map that result to the unchanged
terminal code and never enters Running. The private snapshot's `classify()`
calls the same pure policy classifier and cannot authorize operations.
All existing malformed native query paths continue to fail closed.

This slice **does not yet capture full group details** and is **not an
export-capable evidence collector**. Group inventory, OS build provenance,
approved recipient verification and independent review remain required.

## Mandatory design gates before OC-07.2b data export

1. Obtain and verify an externally owned, offline-decryptable public
   encryption recipient (prefer the standardized `age` file-encryption
   format and pinned toolchain, not custom encryption or hash-only disclosure).
   Never generate a private decryption key on a public CI runner.
2. Restrict export to an ephemeral **github-hosted Windows** execution on
   a reviewed, protected `main` commit, never an untrusted PR job.
   GitHub environment flags by themselves are **not** security authority.
3. Capture provenance inside the trusted harness: exact Git commit/tree,
   signed binary SHA-256, workflow run/job, OS build, service identity and
   restricted SID status. Bind this metadata to the same encrypted receipt.
   Do not treat the CI runner user token as the SCM process token.
4. Define an ACL-protected, single-use handoff with authenticated SCM
   process identity and non-replayable challenge. Do not accept caller-
   controlled file paths, inherited arbitrary environment data, named-pipe
   clients or alternate service installations as proof. Limit buffer bytes,
   record count, read/write permissions and duration.
5. Encrypt **before** creating an artifact or logging any data. Never
   print plaintext names/SIDs, ciphertext keys, raw tokens or privileged
   material. Restrict recipient/key rotation, retention (maximum one day),
   upload permissions and cleanup, with explicit failed-cleanup denial.
6. Independently verify that a separate attacker principal cannot read,
   replace, spoof or retrieve the evidence, and that malformed/partial
   encryption or provenance mismatches leave the service Stopped with
   non-release denials. Negative tests are mandatory on the real Windows SCM.

Do not use `SeChangeNotifyPrivilege` or `SeImpersonatePrivilege` as an
implicit allowlist; none has been approved. OC-07.3 is a separate documented
security review **after** decrypted evidence is assessed. C5 native file I/O,
authenticated IPC, policy custody, revocation, adversarial D and release E
remain blocked.

## Testing and nonclaims

- Rust TDD: absent private type failed before implementation; tests exercise
  code 3 for unreviewed privilege, code 4 for enabled dangerous privilege,
  code 1 for no enabled privilege, code 5 for invalid evidence.
- Node contract asserts no exposed snapshot API or native log/file writer
  and unchanged terminal SCM classification. Full Windows SCM CI
  acceptance and protected postmerge remain separate required gates.
- **This slice creates no evidence artifact and approves no privileges.**
