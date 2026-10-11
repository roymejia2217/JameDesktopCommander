# T011-C3 — Persisted filesystem policy candidate source

**Status:** Experimental, additive ConfigManager API, **not** used to authorize
production MCP operations. Base: `7ba0ba21e70d7957ef37aa25bb75e26d5a692c4a`.

## Purpose

The existing `getAllowedDirectoriesForFilesystem()` returns an array without
a policy revision, sometimes from a watcher-updated cache. The experimental
T011-C2 manager instead requires a trusted `{ mode: 'restricted', revision,
allowedRoots }` provider. T011-C3 makes a **disk-observed candidate**, not a
false promise of revocation-atomic authorization.

The additive `ConfigManager.getFilesystemPolicyCandidateSnapshot()` waits
for its observed write queue, refuses known pending/coalesced writes and failed
watcher state, re-reads persisted JSON (no cached policy fallback), checks that
the local write generation did not change during the read, and parses the
candidate using `parseFilesystemPolicyCandidate()`. I/O/read failures deny
with a generic error; malformed allowlists also deny. It **does not** alter
the existing `getAllowedDirectoriesForFilesystem()` contract or write config.

The parser supplies a frozen copy of the observed policy plus a deterministic
SHA-256 digest of its mode and root list. Modes are distinguished exactly:

- `restricted`: nonempty absolute, normalized and unique directory roots,
  excluding volume roots. No symlink/canonical identity proof is claimed.
- `unrestricted`: the existing explicitly empty `allowedDirectories: []`
  or any configured `'/'` legacy wildcard. This mode must **never** be
  fed to the native restricted manager as an authorized sandbox.
- `legacy-unset`: absent `allowedDirectories` key (historically processed
  by the existing default-home policy path); deliberately distinct from
  explicit unrestricted mode.

Roots expressed as `~`, relative, nonnormalized, duplicate, empty or
volume-root paths are denied as **unsupported candidate inputs**. Existing
user configuration remains unchanged; no silent home expansion or access
widening is introduced.

## Proof obligations and limits

Seven focused node:test tests validate immutable data, stable revisions for
unrelated settings, externally replaced persisted config, explicit
unrestricted vs legacy-unset, malformed/noncanonical roots and disk errors.
The tests exercise `ConfigManager` through compiled `dist` code on the
normal Windows/Linux CI matrix. Tests isolate watcher scheduling by closing
the fixture watcher; production watcher behavior is unchanged.

**Not a trusted revocation transaction:** A digest detects an *observed*
change, but not ABA (A → B → A), nor a process changing config after the
read, nor filesystem root replacement between policy load and native open.
The existing cross-process config locking protects individual writes, not
the time between an authorization snapshot and a file operation. A valid
candidate MUST NOT be passed directly to real JDC file handlers until a
separate monotonic durable policy version, process synchronization and
capability-safe root acquisition are established and adversarially tested.

The T011-C2 `RestrictedCapabilityPolicy` remains test-only and is not
instantiated here. Its ambient native constructor, synchronous file I/O,
limited byte API and incomplete PDF/DOCX/Excel/search/edit/directory coverage
are unsuitable for production. This slice adds no native distribution,
services, gateway, installed runtime, or official release.

**Release gate:** The originally demonstrated `validatePath()` TOCTOU
remains OPEN. Complete T011-C3+, T011-D and T011-E, including independent
pre/postmerge native and portable artifact audits, before any production
security or readiness claim.
