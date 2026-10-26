# T011-C4s — independent Windows Registry policy epoch/digest anchor

**Status:** security feasibility and real-SCM acceptance, non-release. No authorization or policy activation.

## Contract

The dedicated Windows authority service may **observe**, never create/update, a fixed
administrator-provisioned registry value at
`HKLM\SOFTWARE\JameDesktopCommander\Authority\EpochAnchor\PolicyAnchorV1`
in the explicit 64-bit registry view. It is a single `REG_BINARY` of exactly 40 bytes:
8-byte network-order positive u64 epoch followed by 32 bytes of SHA-256 policy digest.
A single value avoids torn observation of two separately updated registry fields.

The kernel service identity is verified first; the key is opened read-only through
official Win32 `RegOpenKeyExW` with `REG_OPTION_OPEN_LINK` and `KEY_WOW64_64KEY`.
The opened key is inspected through `GetSecurityInfo(SE_REGISTRY_KEY)` before
`RegQueryValueExW` reads the binary value. The owner must be SYSTEM or
Administrators; the DACL must be protected and contain exactly three noninherited
allow ACEs: SYSTEM and Administrators with exact `KEY_ALL_ACCESS`, and the
independent service SID with exact `KEY_READ`. All other identities, flags,
rights, missing/wrong-type/oversized values, epoch zero and all-zero digest deny.
No error path restores a default or grants permission.

An `ObservedEpochFloor` has private fields and a non-authorizing exact match
operation over **both** epoch and digest. A rejected old epoch or same-epoch
different digest is a mandatory policy condition, but matching is NOT a grant.
Only a separately authenticated, reviewed policy loader could eventually compare
a fully verified database policy snapshot with this observation.

## Adversarial Windows proof

`test/security/t011-windows-registry-epoch-acceptance.ps1` is restricted to
ephemeral GitHub-hosted Windows runners. It provisions the exact temporary registry
location and descriptor via the OS administrator, registers the canonical
restricted SCM virtual service account, and runs a debug-only observation example.
The positive verdict additionally checks the service **cannot open the key for
write**: `RegOpenKeyExW(KEY_SET_VALUE)` must return real Win32 access denied (5).
Invalid epoch, wrong digest at identical epoch, missing value and foreign
registry ACE must each yield a distinct fail-closed observation status.
All resources must be removed even on test failure; no user host is touched.

The test uses synthetic policy digest bytes solely to prove register admission;
it does not authenticate policy content or exercise a real SQLite transaction.

## Remaining production blockers

- The checked-in SQLite store still opens by pathname; no actual protected
  directory/DB handle, signed policy provenance, digest computation or
  transactional high-water update protocol has been integrated.
- An administrator-controlled registry watermark resists rollback by the
  **less-privileged service**, assuming the Windows Registry key hierarchy
  is provisioned and guarded. It does not defend against compromised
  administrators, offline hive replacement, rollback of the entire OS image,
  VM snapshots, compromised kernel, or attacker-controlled trusted updater.
- Revocation semantics and atomicity between the SQLite transaction and
  the registry update remain to be specified. Until then mismatch **DENIES**;
  never auto-heal the DB or reduce the registry epoch.
- The main service remains deny-only; no named-pipe IPC, public capability,
  N-API bypass, hardlink authority, or migrated MCP handlers are enabled.
- The test-specific `HKLM` provisioning must not be used as an installer.

**Release verdict:** `releaseEligible:false` and issues #124/#139/#148 remain P0.
