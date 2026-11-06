# #270 Windows operator preflight: read-only identity evidence

Status: **experimental / non-shipping / no authorization / T1 incomplete**.

## Scope and verified facts

- Source crate: `native/tunnel-operator-authority`.
- The process SID comes from a bounded `GetTokenInformation(TokenUser)`
  query on the kernel's `OpenProcessToken` result, not environment variables.
- The registered task user is read from the **local** Task Scheduler COM
  service (`ITaskService`, root folder, task definition, principal UserId).
- Windows resolves that Task Scheduler user to binary SID using
  `LookupAccountNameW`, then compares it with process TokenUser bytes.
- Missing registrations, malformed names, invalid SIDs, failed native API
  calls, and account mismatch yield sanitized, non-authorizing observations.
- Windows real-host tests cover identity equality, mismatch, malformed SID,
  absent task and task-name traversal. A read-only probe on the installed
  task printed `READ_ONLY_TASK_SID_EQUALITY_NOT_AUTHORIZATION`.
- No secret bytes, task XML dumps, SID values or credential paths are logged.
- The crate is not invoked by MCP, the tunnel, credential rotation, or UI.

## Explicit security boundary

**SID equality is not a permission grant.** Remote MCP subprocesses may use
exactly the same account as an interactive operator. The Task Scheduler
registration is independently observed, but its executable identity,
registration DACL, ancestry, profile and provenance are not established here.

## Remaining gates before any operational backend or T1 closure

1. Obtain the canonical, independently provisioned installed task identity,
   expected executable, effective command/profile, integrity and registration
   DACL, without trusting a supplied task name as authorization.
2. Read protected credential files and *every untrusted ancestor* by native
   handles. Verify owner, effective DACL, reparse points, links and installed
   target identity, with actual Windows adversarial fixtures. No path-check /
   reopen race, broad ACE, shared-writer or alias may be accepted silently.
3. Prove genuine local-operator provenance/consent independently of matching
   SID (a remote MCP-originated call may share the operator's SID).
4. Bind the evidence to an installed generation/instance and durable STOP,
   then establish a single reviewed, versioned, fail-closed local CLI entry.
5. Preserve negative tests and run on real Windows and hosted CI; Linux must
   be handled by its own audited systemd and filesystem adapter.
6. Reuse `src/platform/tunnel-credential-transaction.ts`, never infer that
   this observer authorizes it or that a running task authenticates MCP.

## Acceptance verdict for this slice

**PASS**: native TokenUser and Task Scheduler principal observation.
**NOT PROVEN**: caller origin, file custody, task ownership, rotation or
service lifecycle authority. #270 and parent #248 remain open; production
release remains NO-GO independently of #124, #139, #148 and #150.

## Next T1 sub-slice: private file metadata observation (non-operational)

The same crate now has a Windows-only `observe_private_file_custody`
function for a **caller-provided fixture root and relative path**. This is
read-only and never opens a credential's content bytes. It acquires Windows
handles requesting `READ_CONTROL | FILE_READ_ATTRIBUTES` and excluding
`FILE_SHARE_DELETE`; checks a root and each descendant while handles remain
open; rejects file/directory type mismatch, reparse-point objects, final
files with link count other than one, invalid relative paths and DACLs with
ALLOWED ACEs for principals other than the process TokenUser, LocalSystem
or builtin Administrators. Owner/DACL are queried on the opened handles,
not through a separate pathname security query. Errors remain sanitized.

Real Windows fixture tests must prove both an explicitly private NTFS ACL
and negative hardlink, junction, unsafe child/parent allow ACE and invalid
path cases. The test fixture itself uses Windows `icacls` on disposable
objects, not the installed tunnel or its credential reference.

**Limitations that still deny production authority:** the supplied root has
no independently trusted installation/provenance binding; ancestors above
that root are not checked; DACL snapshots are conservative but not a proof
of actual access under every SID, privilege or ACE variant; a valid hardlink
count at one instant does not prevent a future alias; a same-SID attacker
may change its own objects, tokens or ACLs. Future operations must be based
on authenticated local-operator consent, installed task/profile identity,
handle-bound target and generation fencing. A preflight result cannot be
cached as a permission or used to bypass further checks. No secret writes,
service control, broad path IPC or rotation is connected to this module.

**Increment verdict:** native metadata observation only; #270 T1 remains
in progress and the product stays release-ineligible. Hosted Windows/Linux
CI and independent security review must pass before integrating this slice.
