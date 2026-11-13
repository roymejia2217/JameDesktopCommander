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

## T011-C4p — Linux kernel Unix-peer observation checkpoint (non-shipping)

The separately tracked #139 peer-identity slice adds
`native/authority-service/src/linux_peer.rs` and a private, cross-platform
`peer_policy.rs`. These are **non-authorizing** building blocks. The service
binary still checks its **own** identity and terminates with
`E_POLICY_UNAVAILABLE`; no listener, socket path, policy bootstrap, root
capability, administrator account or filesystem operation has been added.

On Linux, a socket's `SO_PEERCRED` is read using the existing pinned `libc`
dependency. A failed kernel call, incomplete `ucred` structure or nonpositive
PID denies observation. In private tests, the expected UID/GID are separate
from the authority's UID and primary GID, nonzero and paired with an independently observed
positive PID. The candidate additionally denies a peer with the service's
primary GID even if its UID differs; shared group DAC could otherwise expose
service-owned state. A **synthetic** positive comparison is a contract test, **not**
proof that an administrative client identity exists on any deployment.
No identity claim in a socket payload, JSON field, environment variable or
process title becomes a grant.

Important unsatisfied proofs remain: the kernel reports peer credentials from
**connection time**; passing or reusing a file descriptor may require stronger
session/channel custody and request authentication. No independently protected
client-principal lookup or policy revision/epoch binding is implemented. No
supplementary-group, privileged-helper, mount, ACL, hard-link or operation
revocation guarantees follow from these tests. Windows named-pipe peer token
and impersonation review remains entirely separate. The first real-host
Linux cross-process check runs in the existing native T011 CI matrix and
is independent of the Windows-only Rust policy tests. It proves a
separate PID but **not** a distinct client UID in the current fixture;
independent cross-principal admission and process-descriptor custody
remain pending OS acceptance gates.

**Do not treat this checkpoint as a remediation** for #124, #139 or #148 or
change `releaseEligible:false`. Production code must not import the isolated
experiment; missing OS-backed authority and pinned handles continue to deny.

## T011-C4q — CI-only Linux peer identity across distinct operating-system principals

A dedicated ignored Rust test in `native/authority-service/src/linux_cross_principal.rs`
runs only when explicitly invoked after the existing native T011 Linux
systemd-sysusers and cross-principal custody checks. It refuses non-GitHub,
non-Linux or non-hosted environments. The test runner is a non-root
principal; the client connects via the established system account `nobody`
using standard, non-interactive `sudo`. `/usr/bin/id` obtains the
independent operating-system UID/GID, and the kernel-issued `SO_PEERCRED`
identifies the connecting PID, UID and primary GID. A byte message reporting
the child's PID is **not** an authentication input: it is compared against
the separately observed kernel PID. The private classifier rejects the
wrong account and any client sharing the authority's primary GID.

The socket is test-only, single-use, owned under the disposable runner's
temporary directory, with a randomized pathname and deliberately relaxed
write permission solely to test a cross-UID connection. It handles no file
or policy operations, has a bounded listener and read timeout, and removes
its endpoint and terminates its subprocess on exit. The explicit workflow
step requires a positive test marker **and exactly one executed passing
test**; a missing ignored test or a zero-tests match must fail the job.

**Scope limitation:** this demonstrates a real connection across different
UID/GID accounts, with the runner acting as the test server and `nobody`
as the client. It does **not** establish a protected production client
identity, the dedicated `jdc-authority` service as the listening server,
supplementary-group confinement, executable custody, FD-passing/reuse
safety, session authentication, durable policy epochs or handle-bound
filesystem operations. The authority remains `E_POLICY_UNAVAILABLE`.
`releaseEligible:false` and P0 #124/#139/#148 are unchanged.
