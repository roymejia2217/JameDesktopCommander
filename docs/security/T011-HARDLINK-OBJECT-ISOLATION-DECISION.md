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

### Non-release opened-object post-read guard (#148)

The experimental native bounded read now rechecks the link count on the
**same opened file object** after consuming a bounded number of bytes and
before releasing any of them. A deterministic real OS-thread test adds an
exterior hard link after the initial handle-based preflight, proves identical
file identity, requires typed denial, and checks that exterior bytes are
unchanged. A legitimate single-link read succeeds after removing the alias.

This closes that specific interleaving, **not invariant O**. A link created
after the final snapshot or removed before it can escape detection. Nor does
this prove principal-isolated storage, policy revocation, or end-to-end MCP
handler routing; the four original #147 adversarial cases remain required.
No production capability, native addon, or release eligibility is enabled.

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

**Staged-replacement race evidence and residual gap (2026-10-31):**
`RootedDirectory::replace_existing_file_staged` originally checked the
opened destination file's link count before preparing its private staging
file and later renamed onto the destination **name**. Two deterministic
Windows real-kernel OS-thread tests proved distinct policy failures (unexpected
`Ok(())` where the restricted operation had to DENY): (1) creation of an
outside hard link after the original preflight and staged-file sync; and
(2) moving the original single-link file aside and substituting an outside
object under the original destination name while the opened original handle
remained valid. These are measured RED cases, not hypothetical races.

The experimental non-shipping PR #234 adds a link-count recheck through the
**same opened original handle**, then compares that handle with a fresh
**pinned-parent-relative opened handle** of the final destination name.
In the two measured interleavings the implementation now returns
`E_REPLACE_SHARED_OBJECT` or `E_REPLACE_OBJECT_CHANGED`, respectively,
preserving exact original/exterior bytes and removing the private staging
file. Native Windows and Linux CI passed at code HEAD `2b3f424`;
this later documentation correction does not change the native implementation.

**Unresolved, production-blocking:** both observations still precede
`rename`; an attacker who can mutate the destination namespace between
the final identity check and commit can invalidate the decision. Neither
`nlink == 1` nor `same-file` comparison proves the origin of the object or
provides an atomic compare-and-replace. A privileged bind mount remains a
demonstrated Linux counterexample to storage separation without a defended
mount/principal model.

**Conservative no-release boundary (2026-10-31, PR #234):** the
staged-replacement method and the protected staging capability now compile
**only under Rust `cfg(test)`**. The test-visible method returns
`E_REPLACE_ATOMICITY_UNPROVEN` before any staging write or destination
mutation. Its former handle-relative replacement algorithm remains private
to the native OS fixture tests via an explicitly named
`replace_existing_file_staged_fixture` entry point, so genuine positive and
adversarial cases continue to execute without exposing a callable replacement
method in normal builds. A Rust `compile_fail` doctest verifies the public
method is absent in the normal library artifact. This does **not** establish
invariant O or authorize any read/write/rename route.

**Create-only publication counterexample (2026-10-31, PR #234):** a separate
real Windows OS thread created a hard link outside the permitted root after
the experimental `create_new_file` opened a zero-length destination but
**before** the writer emitted bytes. The opened handle remained valid, the
writer returned success, and the outside alias received the entire payload.
The earlier create-only competition test (both threads racing to create the
**same name**) did not cover this second interleaving. The evidence is retained
as an explicitly unsafe test-only **negative counterexample**: the fixture
must prove the alias was created at zero length, refers to the same kernel
object and receives the bytes. It must **never** be mistaken for an accepted
security behavior. The ordinary-build `create_new_file` API is now also
absent under `cfg(test)`; the test-visible method returns
`E_CREATE_ONLY_CUSTODY_UNPROVEN` before any creation. Existing positive and
adversarial tests call the separate `create_new_file_fixture` implementation,
and a normal-library `compile_fail` doctest verifies the gate. This is a
deliberate feature exclusion, not a proof that create-only is safe under an
attacker-writable namespace. A future approved implementation must make the
entire write complete **before** publishing the new inode and prove
private-staging, no-overwrite publication and principal custody on both
operating systems.

**Test-only no-overwrite publication study (2026-10-31, subsequent to PR
#234):** a separate native Rust fixture creates and syncs the full payload
in a staging directory, then uses `cap-std::Dir::hard_link` between **two
preopened directory handles** to create the final destination name. A
deterministic OS-thread test proves the destination is absent until after
full staging sync; another installs a real outside hardlink under that
destination name before publication, verifies the no-overwrite link fails,
and preserves the outside bytes and alias identity. The staging name is
cleaned after the publication attempt. **This is not a production API**:
the entire fixture exists only in `cfg(test)`, and the public methods
remain excluded from ordinary builds.

A third OS-thread fixture demonstrates the **missing custody proof**:
when the temporary directory is accessible to the attacker's principal,
an outside hardlink can be created to the already-written staging inode,
exposing its full contents **before** destination publication. This is
recorded as an explicitly **negative security counterexample**, not
evidence of confidentiality. A complete design still needs separate
principal/ACL and filesystem attestation, same-volume/cross-volume
acceptance, no-overwrite collision semantics, crash/cancellation recovery
and review of all original #147 attacks before any operation may ship.

**Distinct-principal prepublication staging proof (2026-10-31, hosted
acceptance extension):** the existing Linux and Windows custody acceptance
scripts now test a separate unpublished staging file under the already
protected state directory. On Linux, the service principal
`jdc-authority` must create the file and successfully form a same-volume
hard link to its own object, with kernel device/inode identity checked.
The independent `nobody` identity must fail to read, link, append,
remove or create another entry in that protected directory. On Windows,
two independent disposable unprivileged SIDs test equivalent owner
positive link/same-object and attacker read/link/write/unlink/create
denials under an inheritance-disabled NTFS DACL. Both scripts check exact
content digests before and after the attempts, require no attacker alias,
and remove the temporary staging name. The scripts require disposable
hosted CI; they are never executed on the installed user host.

**Scope of this proof:** the real tests demonstrate separation under the
specific CI principals and ACL/mode state, not immunity to an attacker
already sharing the service UID/SID, elevated privileges, inherited
handles or a changed parent/mount topology. The same-principal stage
leak counterexample above remains valid. A **fourth** native OS-thread
counterexample separately proves source-name substitution after full staging
sync but before publication: an attacker with write access to the staging
namespace renames the approved inode aside, installs a distinct attacker
inode under the original staging filename, and retains its own hardlink.
The test-only publisher succeeds and binds the destination name to the
attacker's inode, not to the completed writer inode. The exact bytes and
kernel same-file identities are asserted independently. This is **negative
security evidence**, never proof that publication is safe under same-principal
access. An inode identity precheck before publication would remain racy;
production requires independently defended staging custody and an atomic
object-source commit contract or continued fail-closed exclusion. No
production stage capability is issued and no `create_new_file` API becomes available to normal
builds. The original #147 object-isolation requirements remain blocked.

**Windows handle-based publication feasibility (2026-10-31, PR #236,
test-only):** official `SetFileInformationByHandle(FileRenameInfo)` can
rename the **already-open source file object**, rather than look up the
staged source path again. The initial real NTFS fixture failed with
`ERROR_ACCESS_DENIED (5)` without explicit `DELETE` access; after
requesting that right, using a destination filename relative to an
open directory handle failed with `ERROR_INVALID_PARAMETER (87)`.
A strictly isolated test-only variant using an **absolute target path**
and `RootDirectory = NULL` then succeeded: when an OS thread renamed
the original staged file away and installed a different attacker file
under the original name, the destination was the same kernel file object
as the **original open file handle**, not the attacker alias. A separate
real-NTFS race with the destination occupied by a hard link returned an
error, preserving exact original/exterior bytes and same-file identity.

**These results are not sufficient for release:** the demonstrated working
form requires an ambient absolute target pathname and does not establish
destination confinement under a preopened root directory. The relative
root-handle form was **rejected by the tested Windows API invocation**,
not shown safe. The Rust Win32 call and its pointer buffer exist solely
within `cfg(test)`; no shipping authority, file mutation endpoint or
new Windows privilege was enabled. Linux `linkat(AT_EMPTY_PATH)` can
address an open source descriptor, but its general capability requirement
`CAP_DAC_READ_SEARCH` violates the intended unprivileged service
contract; an `O_TMPFILE`/procfs alternative has distinct mount and
privilege prerequisites and requires independent native acceptance.
The next eligible implementation must prove a fully root-relative,
handle-bound and no-overwrite operation on both platforms **without**
adding privilege or ambient-path fallback. Until then deny-only remains
mandatory.

#148 stays OPEN/P0 until a separately reviewed object-custody/atomic commit
contract and the original #147 scenarios prove invariant O on both OSes.

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
