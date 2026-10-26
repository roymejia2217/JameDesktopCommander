# T011-C4q — Windows preopened-state DACL observation boundary

**Status: experimental, non-release.** This module does not define or provision a production Windows state-directory location, install a Windows service, grant an MCP operation, or authorize policy bytes.

## Reviewed scope

`native/authority-service/src/windows_policy_root.rs` accepts an already-opened Windows directory `File` and rejects any call unless the current **kernel process token** passes the existing dedicated SCM service-identity preflight. It reads the security descriptor **by the held handle**, using the documented Win32 `GetSecurityInfo(SE_FILE_OBJECT)`, `GetSecurityDescriptorControl`, `GetAclInformation`, `GetAce`, and SID comparison APIs. The returned Win32 descriptor is released exactly once with `LocalFree`.

The inspected object must be a directory with no `FILE_ATTRIBUTE_REPARSE_POINT`. Its security descriptor must have a protected DACL. The directory owner must be LocalSystem or Administrators, not the less-privileged service identity. Its DACL must contain exactly three supported standard allow ACEs, one each for LocalSystem, Administrators and the independently resolved service SID. Every accepted ACE must have both object and container inheritance (`OI | CI`), so newly created SQLite files and child directories inherit the declared protection. The SYSTEM and Administrators ACEs must include `FILE_ALL_ACCESS` (`0x001f01ff`), and the service ACE must include the NTFS Modify baseline (`0x000301bf`) without `WRITE_DAC`, `WRITE_OWNER` or `GENERIC_ALL`. These are required minimum rights, not a claim that other mask bits are automatically safe. Duplicate principals, foreign trustees, missing inheritance, inherited ACEs, insufficient privileges, invalid SID layout and service permissions to change ownership/DACL all deny. A real SCM-token/NTFS positive acceptance is required before policy activation.

The service SID bytes are obtained through the **existing bounded native SID resolver** rather than a new parser or a string supplied by Node. `ObservedWindowsStateDirectory` retains the input `File` so later code can inspect that same kernel object.

## Still missing — no authority is issued

1. **Trusted directory acquisition:** the Windows installer must define the versioned state path and obtain a component-pinned directory handle under a protected system principal, rejecting aliases and directory replacement. This module does not open an ambient path, choose a destination from `ProgramData`, set ACLs, or accept a request-specified root.
2. **Native positive custody:** the disposable Windows SCM runner must actually use the service's restricted token and a matching protected NTFS DACL to prove a legitimate observation; unprivileged and foreign-principal attempts must fail under real tokens. Unit tests of the ACE policy are necessary but are not that positive acceptance.
3. **Policy content authenticity:** a protected directory DACL does not make `EpochStore::open_existing(path)` a handle-anchored, rollback-resistant store; no durable authorization or service-controlled updates are implemented.
4. **IPC and operations:** no named-pipe peer authentication, rootRef issuance, revocation coordination, hardlink object/content isolation or migrated MCP filesystem handler exists. The Windows SCM executable must remain deny-only/Stopped.

## Quality gates

The existing T011 Windows native job must compile, run the policy unit tests, and pass strict Clippy and rustfmt without weakening checks. Separately, Node 22/24, governance and code scanning must pass at the **same HEAD**. All unresolved #124/#139/#148 release gates remain blocking.

**Security result:** a kernel-handle DACL observation prerequisite only; `releaseEligible:false`.
