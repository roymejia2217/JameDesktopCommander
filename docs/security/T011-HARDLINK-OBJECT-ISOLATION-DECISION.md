# T011 — Hard-link object isolation: adversarial evidence and review gate

**Status:** proposed security architecture decision; **NOT ACCEPTED, NOT IMPLEMENTED,
NOT RELEASE-ELIGIBLE**. Do not use this document as permission to enable native
routing, SCM privileges, restricted-mode writes, or a public distribution.

**Evidence anchor:** protected `main` `9ba0a9a73904fd2d7d676814d18e165d2e02b851`;
nonshipping native experiment in draft PR
[#147](https://github.com/roymejia2217/JameDesktopCommander/pull/147), HEAD
`52a872d63ac3185fcf516cf8a6f5a51cd4bc9c0c`.
Issue [#148](https://github.com/roymejia2217/JameDesktopCommander/issues/148);
prerequisites [#124](https://github.com/roymejia2217/JameDesktopCommander/issues/124),
[#139](https://github.com/roymejia2217/JameDesktopCommander/issues/139), and
[#80](https://github.com/roymejia2217/JameDesktopCommander/issues/80).
Complementary callgraph in
[T011-C handler decision (draft #153)](https://github.com/roymejia2217/JameDesktopCommander/pull/153)
(the referenced document is not yet on protected `main`).

## 1. Required security claim: decide what is authorized

**Invariant N — namespace confinement:** an operation opened relative to a
trusted directory capability cannot traverse to an out-of-root pathname,
including attacker-controlled symlinks, reparse points, and swapped ancestors.

**Invariant O — object/content isolation (the stronger requirement):**
no restricted read can disclose bytes of an object also named outside the
authorized storage domain; no restricted write, append, rewrite, delete, rename,
or metadata operation can alter the exterior object, regardless of in-root
names or aliases present before or during the operation. Outside sentinel
bytes are compared exactly. Preserving an outside filename is not sufficient.

N does **not** entail O. Hard links are multiple names for one file object.
An in-root hard link may satisfy root-relative lookup while disclosing or
modifying an inode/file ID with an out-of-root name. No general-purpose
per-object "this inode originated in the authorized directory" proof follows
from the supplied path or handle.

The user-facing promise must not conflate these invariants. This proposal
**retains O as a release gate** because the existing adversarial acceptance
requires it. Reducing the contract to N requires a separately approved
security/product decision and equivalent user-visible disclosure; it must
not happen by weakening, skipping or deleting the RED tests.

### Tool-catalog authority is a separate boundary

Invariant O is scoped to **filesystem operations actually routed through an
enforced restricted-mode capability** under the independently approved storage
and principal model. It does **not** mean the entire MCP server is sandboxed.
`start_process`, interactive shells, OpenCode providers and `read_file` with
`isUrl: true` have separate process or network authority; a native directory
handle cannot constrain those ambient execution/egress paths. A restricted
filesystem test passing does not establish confidentiality when the same MCP
client can invoke an independently privileged tool.

Before a feature-scoped release, enumerate the full exposed tool catalog,
delegated processes, URLs/redirects, credentials and effective OS principals.
Either enforce separately reviewed tool-specific restrictions and denial tests,
or explicitly exclude the wider isolation claim in the documented deployment
contract. The current `allowedDirectories: []` setting means **unrestricted**,
not a sandbox. This scope clarification does not authorize changing existing
process or network behavior, nor does it relax the four hard-link RED cases.
See the non-shipping handler and URL authority audit in draft PR #153.

## 2. Reproducible evidence and current implementation

Source: `test/security/capability-namespace-swap.test.cjs` on PR #147, tests
`native restricted read`, `native restricted rewrite`,
`native restricted append`, and `final-component replacement`.
The fixture creates an outside byte sentinel, makes an in-root hard link,
checks same `dev` and `ino` plus link count, then invokes
`RootCapability.readBytes/writeBytes`. The teardown *also* checks exact
outside sentinel bytes even when the main operation fails.

Recorded evidence in issue #148:
- Native T011 workflow
  [39543479981](https://github.com/roymejia2217/JameDesktopCommander/actions/runs/39543479981):
  Windows x64 **FAIL**, Linux x64 **FAIL**.
- Unpublished portable workflow
  [39543479984](https://github.com/roymejia2217/JameDesktopCommander/actions/runs/39543479984):
  Windows x64 **FAIL**, Linux x64 **FAIL**.
- In the nine-test native suite, five passed and the four hard-link cases
  failed. Outside bytes were actually modified on rewrite, append, and
  final-component replacement. These are failures, **not accepted xfails**.

The nonshipping native probe uses `cap_std::fs::Dir` and
`OpenOptions` in `native/capability-probe/src/lib.rs`, with exposed
`RootCapability.read_bytes` / `write_bytes`. The experimental runtime
has **not** been wired into production MCP handlers. The evidence disproves
its claimed O property; it does not demonstrate a shipped handler exploit.

### Non-release read postcheck evidence (issue #148)

The native handle-bound bounded read now rechecks the link count on **the
same open file object** after consuming at most the configured byte budget and
before returning any bytes. An actual OS-thread hard-link insertion between
the first opened-handle snapshot and the read is an explicit deterministic
RED-to-GREEN test: both real names must refer to the same file object,
the caller receives a typed denial, exterior bytes remain exact, and a
legitimate single-link read still succeeds after removing the alias.

This narrows one observed race window; it **does not** provide invariant O:
a link can still be introduced after the final snapshot or removed before
it. It also does not prove a principal-isolated storage domain, immutable
root provenance, or policy revocation during an in-flight read. Do not count
this test as one of the four missing MCP-level #147 GREEN cases, or permit
production read routing based on it.

### Disposable cross-volume OS-principal acceptance (non-release)

The #148 experimental native matrix now includes a dedicated **fail-closed**
OS isolation proof on both supported platforms. Linux mounts a genuinely
distinct `tmpfs` with the `jdc-authority` UID/GID and restrictive mode;
Windows creates and formats an ephemeral NTFS VHD in the GitHub-hosted runner
and grants the volume root exclusively to its dedicated service SID,
SYSTEM and Administrators. Separate unprivileged attacker identities must
succeed at creating a **real same-volume hard link** in their own storage,
but must fail to import an exterior name into the protected volume.
Administrators must also be unable to create cross-volume hard links
(the filesystem boundary, rather than just an ACL denial). Independent
device/disk identity and exact exterior-byte integrity are verified. Runner
setup or positive controls failing is **FAIL**, never a skip or a success.

These are deployment-feasibility **experiments**, not proof that arbitrary
user-supplied `allowedDirectories` already occupy dedicated volumes, that
a malicious administrator or remount cannot introduce another object
namespace, or that Windows reparse/mount aliases are eliminated. Nor do
they show that the production native service runs in such a volume, or
that its MCP operations and in-flight revocations are already secured.
The required object invariant O and the four original PR #147 RED cases
remain open until the deployment model and real SDK/portable flows
independently enforce these conditions.

### Administrator-controlled Linux bind aliases (non-release negative proof)

The disposable Linux native CI acceptance also requires a **real privileged
file bind mount** from an exterior attacker-owned filesystem into the dedicated
`tmpfs` service domain. The exterior directory is private (0700), so the
`jdc-authority` principal cannot traverse the original exterior pathname.
The file itself is made readable (0644) for this discriminating test. A
privileged administrator then bind-mounts that file over an ordinary file in
the isolated service root. The fixture must verify a real mountpoint, the
**same kernel device/inode object** at both names, successful read through the
imported alias by the service principal, a denied direct exterior-path read,
successful unmount, and an unchanged exterior SHA-256. Failed setup is FAIL,
not a mock denial, skip, or authorization success.

This is an intentionally **negative security observation**: a privileged
mount administrator can defeat object-isolation assumptions that rely on
separate device identities alone. It does **not** show that an unprivileged
attacker has `CAP_SYS_ADMIN`, that actual production native handlers accept
mount-boundary traversal, or that invariant O is enforced. Candidate A
requires a separately approved, OS-attested mount namespace and mount-authority
custody model, including startup and in-flight changes, and Windows
reparse/mount-point parity before any release claim. The test is disposable,
runs only on the GitHub-hosted Linux native acceptance job, and does not
install or enable a service on the user's Windows host.

Kernel semantics: [mount(2) MS_BIND](https://man7.org/linux/man-pages/man2/mount.2.html)
and [mount(8) bind mount](https://man7.org/linux/man-pages/man8/mount.8.html).

## 3. Platform constraints and unresolved assumptions

| Dimension | Linux | Windows |
| --- | --- | --- |
| Hard-link identity | Multiple names share an inode; links cannot cross mounted filesystems | NTFS names reference the same file on one volume; changes through one hard link affect the others |
| Lookup primitive | A directory FD and `openat2` resolution restrictions can support N; they do not enumerate all names | Handle-relative resolution/reparse restrictions may support N after independent native proof; they do not establish O |
| OS protection | `fs.protected_hardlinks=1` restricts cross-ownership/source-permission creation but is **not** a blanket same-user alias ban | NTFS ACLs/service-token privileges govern who can create/open links; same-volume aliases remain possible if permitted |
| Required review evidence | Filesystem, mount namespace, user/UID, directory ownership/modes, link/mount creation rights, whether other principals can write the root | Actual token SID/privileges, NTFS ACL and share modes, filesystem/volume, link-creation rights, junction/reparse/mount scope |
| Unproven scenario | Same UID creates or changes aliases concurrently, or an existing alias predates startup | Same token/privileged principal can create aliases or mutate namespaces, or an existing alias predates startup |

Official references:
[Linux linkat(2)](https://man7.org/linux/man-pages/man2/linkat.2.html),
[Linux kernel protected_hardlinks](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html),
[Microsoft hard links and junctions](https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions),
[CreateHardLinkW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createhardlinkw).

A link-count check is **not** a universal solution. It can sometimes reject an
already multiply linked object *after a handle is acquired*, but does not
identify where external names reside or guarantee they cannot be created
during an operation. `realpath`, pathname prefixes and `O_NOFOLLOW`
address different namespace problems. Neither `nlink == 1` nor an absolute
file path proves the stronger external-object invariant.

## 4. Candidate deployment contracts: review, do not infer

**Candidate A — independently isolated storage and principal (preferred
investigation, NOT approved).** Provision an explicit storage domain whose
file objects cannot also be named outside it under the defined filesystem/
volume and mount model. Use a separate least-privilege OS identity with
custody of that domain and deny unauthorized hard-link creation, directory
mutations, bind mounts and alias import. Prove the full model, including
preexisting aliases and principal transitions, from actual confidential
native evidence. An independent reviewer must explain why an attacker in
scope cannot create cross-boundary aliases while an operation is in flight.
On Linux, a separate filesystem/mount can stop ordinary cross-filesystem
hard links, but mount aliases and the principal's authority need explicit
proof. On Windows, NTFS hard links cannot span volumes, but volume identity,
reparse and token privileges remain gates. This is a deployment model, **not**
a currently shipped configuration.

**Candidate B — conservative feature-scope refusal (safe fallback until A
is proven).** If storage provenance, ownership, native addon identity, OS
principal, or the object-bound operation cannot be proven, restricted-mode
access to the affected operation returns typed `DENIED`, `UNSUPPORTED`
or `UNAVAILABLE` **before a read leak or any mutation**. No fallback to
`validatePath()` plus Node `fs.*`. This is an architectural acceptance
condition for a *future* adapter; this proposal does not change the current
shipping runtime. A useful authorized positive path must still be proven,
rather than shipping a silent "always unavailable" implementation as a
complete solution.

**Candidate C — weaken O to N:** **REJECTED AS AN IMPLICIT FIX**. Could only
be considered by an explicit separately reviewed change to the security
claim, deployment boundary, threat model, negative-test criteria and UI
warnings. A "green" test obtained merely by redefining outside-object
integrity has no evidentiary value for the originally requested protection.

## 5. Operation-level implications and proof plan

| Operation | Required authorization and failure behavior |
| --- | --- |
| Read / preview / structured decode | Acquire the permitted object before reading; never expose exterior bytes via any alias. If object provenance is unknown, deny before I/O. Secondary document inputs require separate grants |
| Append / in-place rewrite | Identity and write authority must hold for the **opened object**, not only its filename. Reject shared aliases or unprovable isolation **before** modification |
| Transactional rewrite | Stage private output and atomic replacement only under a reviewed root-bound parent handle, with controlled expected-object identity, cancellation and rollback. Renaming a new object may preserve old outside bytes, but does not prove the read path or append path safe |
| Move / rename / unlink | Both source and destination parent objects and storage domains need authorization; define behavior for cross-root/cross-volume moves, alias deletion and partial failures |
| Search / external processors | Never hand an ambient pathname to `ripgrep` or a document library and assume a native capability applies. Use safely acquired bytes/handles or typed unsupported response |
| Policy changes / process failure | Hold immutable policy and native object lifetime throughout the operation. Revocation, wrong-architecture addon, cancellation or unavailable backend must not enable pathname fallback |

**Execution order and acceptance, all mandatory:**

1. Obtain independent review of **N versus O** and Candidate A/B operating
   conditions before choosing an implementation. Record eligible users,
   filesystems, ACLs, device/mount boundaries, token ownership and who may
   create/remove links. Unverified host conditions mean **no-go**.
2. Resolve FFI pointer ownership/lifetime **#124** and SCM privilege custody
   **#80**; no privileged identity activation or secret export for this study.
3. Preserve all four existing #147 RED cases unchanged. Prove normal in-root
   read, append, rewrite and rename on both native OSs; no partial outside
   mutations. A fixture unable to install/verify the hard-link attack must
   FAIL or be explicitly inconclusive, never PASS.
4. Add separately correlated concurrent attacker/worker cases: preexisting
   alias, alias introduced after handle acquisition, final-name replacement,
   mount/junction variation, and cancellation during writes. Record proof of
   adversary success and compare outside bytes before/after. Sequential swaps
   alone do not establish a general concurrency guarantee.
5. Route all relevant MCP handlers only after **#139** review. Exercise the
   official MCP SDK against an independently restored Linux/Windows candidate
   and exact source/provenance digest. Denials must use the documented UX error
   taxonomy and preserve safe authorized workflows without unbounded memory.
6. Require Node 22.19/24, Windows/Linux native CI, Clippy/cargo review,
   CodeQL, protected PR approval, artifact signatures and postmerge checks.
   Only then may a separate security review consider changing
   `releaseEligible:false`.

## 6. Explicit decisions withheld

- **Not established:** that any same-user, same-volume arbitrary allowed-root
  configuration can satisfy O while supporting general read/write/append.
- **Not established:** which Linux mount configuration, Windows service token
  or storage permissions are operationally available to JDC.
- **Not established:** that cap-std, Node-API bindings or the existing probe
  can satisfy O in either supported OS without further architectural work.
- **Not authorized:** disabling #147 tests, declaring a passing T011
  *feasibility* run a security approval, mutating a live SCM host, publishing
  a signed release, or merging without independent review.

**Disposition requested from security reviewers:** explicitly select a
verified Candidate A model with environmental attestations and adversarial
proof, or approve Candidate B denial behavior for each unsupported operation.
Until then #148/#139/#124/#80 remain OPEN and T011 stays nonshipping.
