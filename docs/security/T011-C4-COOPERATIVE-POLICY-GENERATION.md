# T011-C4a — Cooperative persisted filesystem policy generation

**Status:** Experimental, additive policy metadata; **not an authorization
capability**. Baseline protected main:
`c0608cbb50aa1aa8cca242d3fead1ef105c16034` (T011-C3 accepted).

## Problem and limited implementation

The prior T011-C3 policy digest identifies observed content but repeats when
config is changed A → B → A. Cooperative JDC writers already serialize
`ConfigManager.performConfigMutation()` with the repository's existing
cross-process `proper-lockfile` and replace config atomically. This slice
stamps two **internal, optional** fields into the same JSON transaction when
`allowedDirectories` changes:

- `__jdcFilesystemPolicyGeneration`: positive safe integer, incremented
  once per completed cooperative policy mutation, with overflow rejection;
- `__jdcFilesystemPolicyFingerprint`: SHA-256 of the raw persisted
  key-presence and value tuple for `allowedDirectories`, retaining the
  distinction between missing configuration and explicit `[]`.

On a policy mutation, missing fields start at generation 1. Valid existing
fields advance exactly once within the same atomic config write. Ordinary
writes to unrelated keys preserve both fields unchanged. In-place array
mutations are compared against a copied pre-mutation value. Attempts to use
the normal config API to forge these reserved fields fail before disk write.
A stamped config with a mismatching, incomplete or malformed pair is rejected
by the **candidate** parser and by subsequent cooperative mutations; it must
never silently restart its generation. Pending/background writes pass through
the same mutation gate. This is additive: old persisted configs without
metadata remain readable as `cooperativeGeneration: null`; production
`getAllowedDirectoriesForFilesystem()` semantics are untouched.

`FilesystemPolicyCandidateSnapshot.revision` **remains** a deterministic
content SHA-256. The new `cooperativeGeneration` is an independent field.
Both are read directly from persisted JSON by the candidate API, with no
fallback to cached or default authorization. The candidate object is frozen.

## Mandatory tests

The new node:test suite must pass in Required CI at Node >= 22.19. Tests
cover A → B → A (equal digest but strictly increasing generations),
telemetry-only writes, two competing ConfigManager instances using the
same lock, in-place allowlist mutation, reset to legacy unrestricted mode,
mismatching external edits, forged internal metadata, safe-integer overflow,
and incomplete metadata. The older T011-C3 direct external-edit case must
now assert **denial** when changed roots retain the stamped fingerprint.
Do not weaken any existing fail-closed or legacy compatibility tests.

## Security limits — remain OPEN and release blocking

This is a **cooperative protocol, not an adversary-resistant revision
authority**. An external writer can replace *both* JSON fields, erase the
pair or replay a previously valid config file; without a trusted external
monotonic store it cannot prevent rollback/ABA between process restarts.
It also does not provide atomic authorization versus an external mutation
after the read, root handle identity against symlink/junction swap,
asynchronous cancellation, or coverage of the existing filename-based MCP
handlers. The test-only T011-C2 manager is **not** wired to the new candidate.

Therefore `cooperativeGeneration` **MUST NOT be accepted as a security
token**, and no new policy or native addon is deployed to installed hosts.
T011-C4b+ must prove a trusted monotonic persistence/rollback strategy,
transactional policy/handle invalidation and native root identity before
any production filesystem authorization change. T011-D/E remain required;
the original `validatePath()` TOCTOU is still OPEN. `releaseEligible`
remains false; services, tunnels and gateway are untouched.
