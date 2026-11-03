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

**Linux unnamed-file feasibility (non-release):** `O_TMPFILE` and `linkat`
through a preopened `/proc/self/fd` directory and a preopened destination
directory were exercised only in a test fixture on Linux `tmpfs` and the
workspace's `overlay` filesystem, as an unprivileged UID without
`CAP_DAC_READ_SEARCH` in its effective or permitted sets. The fixture proves
that a fully written and synced unnamed inode can be published under a new name
and that an existing hard-link destination is not
replaced. It compares actual device/inode identities and bytes. Unsupported
`O_TMPFILE`, unavailable procfs, or an uninstalled attack is a test failure,
not a passing result. See the Linux [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html)
and [`linkat(2)`](https://man7.org/linux/man-pages/man2/linkat.2.html) contracts.

Three **negative controls** also demonstrate the limits: moving the preopened
destination directory outside the original root before publication exposes the
payload at its new location; and the same principal can create an exterior
hard link to the file after publication. An untrusted ordinary directory used
in place of `/proc/self/fd` can also supply a different object under the source
descriptor number, causing the fixture to publish attacker bytes. All controls
require real operations, object identity and exact bytes. Their passing results
demonstrate these counterexamples, not safety. Procfs provenance, mount topology,
parent and principal custody, cancellation, crash durability, other mounts and
Windows parity remain unproven. This fixture does not provide a production API,
solve invariant O, or change any release gate.

**Verified-procfs fixture follow-up:** the test-only path now also exercises
`rustix-linux-procfs` 0.1.1's `proc_self_fd()` to obtain its own checked
procfs directory handle; a separately created fake directory with a matching
descriptor filename does not redirect this call. The earlier unverified
fixture and its substitution counterexample remain intact. The crate documents
its procfs and mount checks, and is pinned only as a Linux development
dependency already present in the lockfile's transitive dependency graph.
This is a positive test with a fake **sibling directory**: it does not simulate
an attacker replacing or mounting over `/proc`, prove the library's checks
race-free under mount mutation, or establish a production trust boundary.
The other two negative controls and all release gates remain unchanged.
See the [rustix-linux-procfs documentation](https://docs.rs/rustix-linux-procfs/0.1.1/rustix_linux_procfs/).

**Static `/proc` overmount acceptance (non-release):** a fresh instance of
`examples/linux_procfs_probe.rs` obtained the checked handle on the normal
host procfs. In a disposable user and private mount namespace, an actual
`tmpfs` was mounted over `/proc`; `stat -f` confirmed the replacement type,
and a fresh probe exited 1 with `Unsupported`. The mount disappeared with the
namespace. This requires user namespaces and namespace-local mount permission;
failure to establish the overmount is inconclusive, not a security PASS.
It demonstrates denial of this particular static substitution only, not
concurrent mount mutation, procfs impersonation by a privileged principal,
destination custody, or Windows behavior. No CI acceptance is claimed.

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

**Windows NT-native root-relative follow-up (2026-11-02, unpublished local
fixture):** a separate `cfg(test)` Rust helper used
`NtSetInformationFile(FileRenameInformation)` with an already-open source
file handle and an already-open destination directory handle as
`RootDirectory`. Real Windows NTFS tests demonstrated source-object identity
after the staging name was substituted, no-overwrite refusal of a hard-linked
outside destination with exact `STATUS_OBJECT_NAME_COLLISION (0xC0000035)`,
and continued binding to the preopened directory object after that directory
was renamed. A new RED fixture using a one-character basename initially
returned `STATUS_INFO_LENGTH_MISMATCH (0xC0000004)` because the supplied
buffer length was smaller than `sizeof(FILE_RENAME_INFO)`. The test-only
buffer length now includes at least that full ABI structure size; short,
Unicode BMP and supplementary-plane names passed as native source-object
publishes. A subsequent adversarial basename fixture reproduced
`STATUS_OBJECT_NAME_INVALID (0xC0000033)` for a Win32-reserved `|` name
that the helper had not rejected as invalid input. The test-only boundary now
rejects the Win32 reserved characters, control codes, trailing dot/space and
separators/stream syntax before calling NT; source bytes and the destination
directory remained unchanged across the rejected cases. This is a bounded
research validation, not canonical-name security acceptance or production
routing. A follow-up real-Windows native test showed that holding a source
stage with `FILE_SHARE_READ` (no shared WRITE or DELETE) denied a second-handle
rename, **but the same OS principal still created a real external hard link**.
The fixture checked identical kernel file identity, then appended bytes using
the retained writer and observed those new bytes through the outside alias.
The original optimistic assertion that a share-mode lock would prevent the
hard link failed; the retained negative fixture now requires the alias and
its observed outside-byte effect. File share restrictions alone do **not**
establish object/content confinement, even when a source-name swap is denied.
Only a separately attested storage/OS-principal authority model could make
this design eligible for a stronger invariant; no live mutation is enabled.
These narrow outcomes are **not** proof that a moved parent remains
inside the authorized root, nor that untrusted same-principal aliases,
concurrent mount change, cancellation, crash recovery, Linux parity or #124
FFI ownership are secure. Do not add this NT operation to a normal build or
activate a released mutation handler. Host-wide tests, strict lint and
independent review are additional gates; #148 is still fail closed.

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

### Child capability mount-domain admission (2026-11-02, draft #240)

The earlier native `RootedDirectory::open_child` validated only the child
basename, then delegated to `cap_std::fs::Dir::open_dir`. Unlike the bounded
read, listing, and descendant creation primitives, it did **not** compare
the opened child directory's Linux kernel mount ID to its parent. As a result,
a same-device bind mount could become a fresh root capability and subsequent
operations would check against the **imported** mount instead of the originally
authorized storage domain. This is a distinct object-authority escalation,
not an argument that link-count preflights establish invariant O.

The non-shipping Linux native implementation now opens the child with
`open_dir_nofollow` and compares `statx(STATX_MNT_ID)` on the two already-open
directory handles before returning a child capability. A mismatch returns
`EXDEV`; missing mount identity fails closed. The test contract includes a
nonprivileged `/` -> `/proc` mount crossing and a real writable same-device
bind mount whose mount ID is distinct despite identical device/inode. The
positive control opens a legitimate same-mount child and creates a nested
directory. The existing GitHub-hosted disposable mount fixture must execute
the latter case before this change can receive native Linux acceptance.

This closes only an identified mount-hop capability-admission path. It does
**not** establish protected storage ownership, disallow same-principal
hardlinks, prevent a root from being moved during a live operation, or
authorize the existing four #147 invariant-O RED scenarios. Production native
issuer activation and publication remain denied pending independent review.

### Protected-domain operation acceptance expansion (2026-11-02, draft #240)

The existing disposable Linux tmpfs and Windows VHD/NTFS CI fixtures already
exercise distinct real OS principals and separate filesystems/volumes.
Their earlier successful tests established **cross-device hard-link refusal**
and selected read/append permission denials; they did **not** cover the
entire read/rewrite/append/rename/delete operation set under a common
positive-control and exact-byte preservation contract.

The current non-release acceptance expansion adds the following checks to
those existing OS-managed fixtures (no third-party ACL wrapper or live-host
provisioning):

- The actual attacker principal must successfully read, append, rewrite,
  rename, unlink and create objects in its **own** writable directory.
- The actual dedicated service principal must successfully exercise the same
  operations inside the isolated storage domain.
- The attacker must then fail those operations against the service-owned
  object, with the original object's SHA-256 unchanged, no renamed or
  injected entry, and the independently stored outside sentinel unchanged.
  The original **file object identity** must also survive: Linux compares
  kernel device/inode before and after; Windows retains an administrative
  hard-link witness and rechecks same-file kernel identity after the
  attempted mutations, before removing that witness. Matching bytes alone
  are deliberately insufficient to establish identity.
- A test-only Rust probe supplies an explicit native **in-place rewrite**
  operation. The focused Windows RED test initially failed with
  `unknown operation` (exit 101); after implementation, a real
  hardlink-alias test proves that rewriting one filename changes the bytes
  visible through the other name. This is a retained **negative property**
  of same-object hard links, not evidence of containment.

These assertions must run on actual disposable, differently provisioned
Windows and Linux OS principals before any cross-platform acceptance is
claimed. A test passing because an account, tool, mount, or attack setup is
unavailable is an invalid result.

**Scope restriction:** These are OS access-control and storage-boundary
tests, not green results for the original four #147 native-capability
fixtures. They do not prove same-principal isolation, concurrent mount
namespace custody, service-token security on live hosts, full MCP routing
or an independently reviewed issuer. Privileged administrators can still
bind-mount foreign objects in the Linux research fixture; the proof and
its explicit threat-model exclusions must remain visible. The service
continues deny-only pending complete object-domain authority review.

### Native issuer root admission: Linux-only fail-closed boundary (2026-11-02, #240)

This increment moves the **separate-storage requirement into the Linux
issuer's root-to-capability transition**, rather than treating successful
installer fixtures as authorization. `IssuerPolicy::open_root` remains a
non-authorizing, handle-only administrative preflight. The production-only
`SealedDirectoryGrant::from_issuer_policy` and its root revalidation path
instead call `IssuerPolicy::open_custodied_root` after the independently
attested administrative policy/epoch check.

The new admission must observe the following directly from **already opened
kernel directory handles** before returning a root capability:

1. Effective service UID/GID must be nonzero, and production code must pass
   the existing dedicated Linux service identity preflight, including
   filesystem credentials, no-new-privileges and capabilities policy.
2. The policy's final root must be a directory owned by that UID/GID with
   exact mode 0700, located at the root of a **separately mounted
   filesystem**: both mount ID and device must differ from its immediate
   parent. A same-device bind alias is not an isolated storage domain.
3. The mountpoint's immediate parent must be root-admin-owned, without
   group/other write permissions; all intermediate ancestors must remain
   root-owned, must not cross foreign mounts and must not be writable by
   group/other, except for a root-owned sticky directory such as `/tmp`.
   A service-owned parent could let the service rename its own supposedly
   protected mountpoint. Parent and child metadata come from `fstat`;
   mount IDs come from `statx(STATX_MNT_ID)` with no name-based fallback.
4. A failed observation, unknown mount ID, wrong owner/mode, same-device root,
   mutable parent or changed root identity **DENIES** before authority is
   issued. Neither policy JSON nor the MCP client can supply the expected
   device, UID or mount ID.

A pure, cross-platform Rust security decision test must demonstrate
**RED→GREEN** for same-mount, same-device, wrong-owner, wrong-mode,
root-writable-parent and zero-UID/GID cases. A separate hosted Linux
test runs the **actual issuer method** with a disposable root-owned
mountpoint parent, mounted tmpfs and the dedicated `jdc-authority`
principal under `no_new_privs`; it must positively create a child
inside the isolated root and deny a mismatched root reference. Normal
unmounted administrative directories must remain rejected even if
`open_root` can open them by name.

**Scope limits:** This deliberately changes which Linux restricted roots
could become operational: existing ordinary directories are
**unsupported/denied**, not silently reinterpreted as isolated. Windows
issuer parity, unprivileged ownership lifecycle and administrative
provisioning, race-free mount-namespace custody under privileged adversaries,
revocation after concurrent namespace mutation, and full #147 native
read/rewrite/append/replacement adversarial coverage remain distinct
release blockers. These checks cannot make arbitrary same-principal writable
data safe, cannot stop a privileged host administrator and **do not
activate** the native service or any MCP operation.

### Issuer-read E2E fixture migration after mandatory root custody (2026-11-02)

The initial hosted `82f0047` Linux root-admission test **passed 1/1**
under the dedicated service principal but the later Node→systemd→issuer
read E2E returned `E_AUTHORITY_UNAVAILABLE`. That E2E had provisioned its
two policy roots as ordinary child directories under the service-owned
SQLite state path. The stricter issuer correctly rejected both roots:
neither was a separate mount, and their immediate parent was mutable by
the service principal. The E2E's previous positive behavior was therefore
not legitimate proof of object custody.

The disposable hosted fixture now provisions an independent,
root-admin-owned `/var/lib/jdc-authority-roots` mountpoint parent and
two **different kernel filesystems** for the policy roots. Policy bytes
and their independently computed administrative digest/witness are
updated together. No runtime fallback for the old shared-volume roots
is added. The fixture preserves the original binary reads, sequential
list, durable replay, invalid rootRef, and native mounted-alias denial
contracts. It also deliberately mounts a subdirectory of a separately
mounted backing tmpfs as the first policy root; a sibling exterior
file on that backing filesystem has the same `st_dev` but lies
**outside the authorized root subtree**. A privileged administrator
then bind-mounts that file over an in-root name to reproduce the
same-device, different-mount attack. The issuer must deny the alias
and preserve the exterior SHA-256, even though a trivial `st_dev` or
hardlink-count check would miss the attack.

**Crucial limitation:** The backing mount is accessible through a
second, administrator-created pathname solely to construct the
adversarial same-device case. This test configuration does **not**
satisfy the exclusive-origin assumption for production roots, and
the issuer's current owner/mode/mount-ID gate alone cannot prove that
an administrator has not exposed the same filesystem elsewhere.
The test validates fail-closed mount-bound operations under a
privileged attack fixture, not a complete administrator-resistant
origin invariant. Independent review must approve the supported
mount-namespace/provisioning guarantees before #148 can close.

### Windows non-issuing opened-handle volume discriminator (2026-11-02, #148)

The Linux issuer now rejects roots sharing a device/mount domain, but Windows
does not yet have an equivalent production root issuer. This increment adds
a **non-authorizing Windows volume preflight**, using the official
`GetFileInformationByHandleEx` API with `FileIdInfo` and
`FileAttributeTagInfo` on already-open directory handles. The kernel
provides 64-bit volume serials and 128-bit file IDs: equal, missing or
zero volume identities; missing/all-zero file IDs; and non-directory or
reparse attributes deny. An unsupported or failed extended information
query **denies**, without falling back to the legacy truncated 32-bit
volume and 64-bit file index. No ambient pathname is reopened to obtain
metadata, no compiler-unstable API is enabled, and no Windows grant/SCM
activation changes.

The non-issuing `observe_preopened_isolated_service_root` now composes
this predicate **after** the existing real SCM identity and exact protected
root-DACL observation. There is no caller-supplied SID, volume serial or
permission claim. Its public result is the existing data-only observed
handle, not an execution capability. A focused Windows test proved RED
(missing integrated observation, Rust exit 101), then GREEN for the
interactive-user denial and exact typed handle-only signature. The
separate-volume VHD test checks the volume discriminator under the
disposable runner administrator and therefore **does not** establish
the service-token/DACL positive path for this combined observer.

A Windows local unit test must prove that two genuine handles to directories
on the **same existing NTFS volume** are denied. The existing disposable
Windows VHD acceptance creates a separate NTFS disk and runs an
**explicitly unignored** Rust test against the VHD root and a directory on
the system drive. The test requires the different-volume preflight to
accept, and both same-volume controls to deny. The PowerShell fixture
independently verifies actual `Get-Partition` disk numbers and NTFS for
both drives. It also requires an **exact Rust harness test-name PASS line**
and `1 passed; 0 failed; 0 ignored` in the captured native output:
`cargo test --exact` can exit 0 when zero tests match, which must never
count as an OS storage proof. Its established unrelated attacker/service
DACL and cross-volume hard-link attacks continue unmodified.

**TDD for extended kernel IDs:** a new focused case first failed RED
(Rust exit 101) because the prior 32-bit serial and 64-bit file-index
representation could not express two 64-bit volume IDs with identical
lower 32 bits or a full 128-bit file ID. It then passed GREEN after
adopting `FILE_ID_INFO`. Existing real same-volume handle denial
and the explicitly unignored hosted NTFS VHD admission test continue
to exercise the same production preflight implementation.

**Security limits are material:** even a 64-bit Windows volume serial
is only a *necessary discriminator*, not a globally unique immutable
storage-origin credential.
Collision, administrative reformat, duplicated volume images, and alternate
mount paths are not excluded by this preflight. It does not prove the
opened root is really a child of the supplied parent, inspect its owner or
ACL, authenticate a Windows SCM service token, exclude unauthorized aliases
or issue a capability. Those require a stronger, separately reviewed
native volume identity plus protected component-pinned bootstrap and
real service principal. This isolated **data-only** check must not be
substituted for completion of #148 or the four original #147 RED cases.

### Actual Windows restricted-SCM plus isolated-volume observation (2026-11-02)

The existing official disposable Windows hosted-SCM fixture is extended in
place, rather than introducing a new service or installer. Its debug-only,
never-shipped `windows_state_scm_probe` invokes the real
`observe_preopened_isolated_service_root(parent_handle, root_handle)`
under the restricted **NT SERVICE\\JameDesktopCommanderAuthority** token.
The production library implementation requires that token's established
OS identity preflight and the kernel-opened root's exact
administrator-owned DACL, then enforces distinct kernel volume identities
on the open handles. The fixture leaves the existing state-DACL
positive/negative scenarios and their strict SCM service-specific exit
codes intact.

The new acceptance demands ALL of the following on a disposable
GitHub-hosted Windows runner:

1. An administrator-owned, protected-DACL ordinary directory at
   `%ProgramData%/JDC-T011-C4R-*/isolated` on the **same device** as the
   parent must be rejected by the real restricted SCM token (exit 47).
2. A standard 128 MiB expandable NTFS VHD is created and attached using
   Windows DiskPart; its independent physical disk is compared to the
   system disk using `Get-Partition` and `Get-DiskImage | Get-Disk`.
   The VHD is mounted into that empty directory using the documented
   NTFS folder mount-point contract. The exact mounted partition and
   NTFS filesystem type are verified, then its root receives the
   established, explicit administrator-owned three-principal DACL.
3. The actual SCM service must now accept the composed **token + DACL +
   separate-volume** observation (exit 46), deny a service read-only
   root DACL (47), accept its restoration (46), reject an unauthorized
   foreign ACE (47), and accept final restoration (46). Success is
   recorded only after all independent positive and negative steps;
   a stuck-deny implementation cannot pass.
4. Cleanup always attempts service removal, VHD detach **before**
   recursive deletion of the temporary mountpoint, and VHD removal.
   Failure to detach prevents recursive deletion of a still-mounted
   filesystem. This test must never execute on a user computer.

**Security boundary:** This is *non-authorizing* custody feasibility.
DiskPart is an official Windows tool and the fixture runs exclusively
on disposable CI hosts. The verification does **not** prove stable
parent-to-child object linkage across the folder mountpoint, absence
of a second privileged mount or administrative namespace replacement,
nor same-principal hardlink provenance inside the approved volume. It
does not install or activate a production issuer and does not close
issue #148 or supersede the four #147 RED attacks.

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
