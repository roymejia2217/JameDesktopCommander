# T011-C4g — Independent process identity preflight (non-release)

**Status:** Experimental, deny-only Windows/Linux executable. Protected main
baseline: `45a5656376764358588327bcbd71f4d4b83e6571`. There is **no**
broker, exposed IPC listener, policy store, authorized root, native file
mutation or runtime handler integration. The standalone executable always
exits with a nonzero status. It is not an installed Windows service or
Linux systemd unit and MUST NOT be shipped as a functional broker.

## Threat model

The JDC Node MCP process, config editor, model-provided paths and
environment variables are untrusted. Identity cannot originate from
`USERNAME`, `USER`, CLI options, a JSON `rootRef`, PID, inherited
environment, process title or another client-controlled string.
A separate independently administered OS security principal is required
to own service policy, epoch persistence and native filesystem handles.

The new `native/authority-service` crate is an **independent Rust binary
and library**, unrelated to N-API or installed JDC services. It is
presently a preflight, not a broker. A successful process-identity
check is necessary but never sufficient for filesystem authorization.

### Windows x64

The binary resolves the fixed virtual service account
`NT SERVICE\\JameDesktopCommanderAuthority` through
`LookupAccountNameW`, queries its **own primary process token** using
`OpenProcessToken` and `GetTokenInformation(TokenUser)`, and compares
kernel-issued SIDs using `EqualSid`. Missing account, malformed/
oversized API outputs and any mismatch deny. A normal interactive
account cannot set an environment variable to become this token.
The eventual service must be provisioned and its executable, registry,
DACL, privilege policy and SCM configuration reviewed independently.

**Not yet proven:** the service actually launches under the designated
virtual account, protected service SID and DACL isolation, named-pipe
client token and impersonation semantics, cross-user access denials,
impersonating threads, or administrator-tampering behavior.
These require real service-host integration tests; the self-check does
not authenticate a pipe client or attest its own executable provenance.
### Linux x64

The binary looks up the fixed dedicated `jdc-authority` account using
bounded `getpwnam_r` and checks the real, effective and saved UIDs and
GIDs from kernel `getresuid`/`getresgid`. All slots must equal
the resolved dedicated account and the account UID/GID must be nonzero.
Missing account, oversized NSS response, inherited root IDs, divergent
saved credentials, missing system calls and other errors deny.
The code does not parse `USER`, `LOGNAME` or configuration files.

**Not yet proven:** systemd-managed lifecycle, `SO_PEERCRED` client
authentication, supplementary groups, protected directory ownership and
mode, capability bounding, cross-principal acceptance/denial, a
non-replayable epoch store or safe operation on pinned file handles.

## Exact fail-closed startup behavior

The executable performs the kernel credential check before taking any
other action. It writes `E_IDENTITY_REQUIRED` for a missing/wrong
identity and exits unsuccessfully. Even with a correct service identity
it writes `E_POLICY_UNAVAILABLE` and exits unsuccessfully because
authenticated IPC, durable policy and root confinement are **absent**.
No command-line flag, environment variable or alternate execution
path can enable a listener or filesystem operation.

This makes the development-host negative tests reproducible without
installing a privileged service. It does NOT demonstrate that the
correctly provisioned identity is independently isolated. That proof
requires separate real-host integration with a privileged fixture.
## Tests and supply-chain gates

- `cargo test --locked --manifest-path native/authority-service/Cargo.toml`
  exercises a hosted normal-account rejection and a subprocess that
  spoofs common environment claims; it must remain denied.
- Linux additionally tests representative matching and mismatching
  real/effective/saved UID/GID tuples. These are **unit checks**, not
  proof of real cross-user privilege isolation.
- `cargo clippy --locked --all-targets -- -D warnings` and `rustfmt`
  verify build hygiene, without treating warnings as authorization tests.
- Native CI runs the tests on Windows 2025 and Ubuntu 24.04 using
  the pinned Rust 1.91.1 compiler and checks advisories, licenses and
  package provenance using the existing strict native cargo-deny policy.
- `test/test-t011-authority-isolation.js` denies accidental imports of
  the experimental `authority-service` into productive `src`.
- No new runtime dependency, public MCP API, N-API binding, distribution
  target, installed service, tunnel, site bridge or release eligibility.

## Mandatory next proof before authority may become operational

1. Provision a dedicated least-privilege OS principal using a separately
   reviewed, administrator-managed **standard service installer** with
   recovery, uninstall and explicit opt-in. Validate service config,
   executable integrity, OS token, Windows service DACL and Linux
   account/systemd hardening on real hosts.
2. Independently protect the durable policy+epoch state from the MCP
   account. Prove crash/restart, A→B→A replay, rollback, torn writes,
   missing store, concurrent updates and privilege-violating mutations.
3. Authenticate peers over Windows named pipes and Linux Unix sockets,
   and bind peer principal, `rootRef`, policy epoch and pinned native
   root handles in a transaction.
4. Enforce bounded/cancellable I/O and linearizable revocation inside
   the broker, prove zero unauthorized byte mutations, then migrate
   the entire filesystem call graph under separate C5/D/E acceptance.
5. Keep the service **uninstalled** and `releaseEligible` false until
   independent Windows/Linux acceptance and distribution review.

References: Microsoft Windows service user accounts and token
authentication guidance; Windows API `LookupAccountNameW`,
`GetTokenInformation`; POSIX/Linux `getpwnam_r`, `getresuid` and
`getresgid` manuals.
