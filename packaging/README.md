# JameDesktopCommander installer packaging

The official source of versions and GitHub tags is **Release Please**.
Do not version installer binaries manually. The root package.json version,
server.json and src/version.ts are maintained by release-please-config.json.

## Installers (non-release gate)

The existing .github/workflows/distribution-candidate.yml runs on protected
main and pull requests to main. It first builds/verifies an unpublished,
native-capability-disabled portable candidate; then uses the exact same bytes
for platform-specific installable artifacts.

- Windows x64: **Inno Setup 6.7.3** compiles packaging/windows/*.iss into
  an installer EXE. The compiler NuGet archive is SHA-256 pinned, the compiler
  Authenticode signature is checked, and an ephemeral runner performs an
  isolated silent install/uninstall test. The install is per-user. No
  privileged Windows services or registry integration are added.
- Debian amd64: **nFPM 2.48.0** reads packaging/linux/nfpm.yaml; its official
  release archive is SHA-256 pinned. An Ubuntu 24.04 runner validates the
  native package fields, package contents and dpkg install/remove cycle.
  No systemd service, daemon or post-install scripts are activated.
- Each installer input must match the hash-inventoried candidate's source
  commit, platform and runtime entrypoint. The validation module in scripts/
  validate-installer-input.mjs is an input guard, **not** a package builder.

## Pinned official OpenAI Secure MCP Tunnel dependency

The Windows x64 and Debian amd64 **unpublished** installer candidates include
OpenAI's official `tunnel-client 0.0.19` full release bundle. The source is
`openai/tunnel-client`, not a vendored fork. Version, exact archive filenames
and SHA-256 digests are pinned in `packaging/tunnel-client-release.json`.
`scripts/verify-tunnel-client-release.mjs` verifies each downloaded archive
**before extraction or execution** on disposable hosted runners. The official
LICENSE, NOTICE and SBOM/license materials remain alongside the executable.

The installed CLI is under `tools/tunnel-client/` within the JDC directory.
An explicit `--bundled` selection is available for `jdc tunnel install`
on both supported operating systems (and for read-only `jdc tunnel doctor`
on Linux). For example:

```text
jdc tunnel install --bundled --profile-dir <absolute-existing-profile-directory> --profile <existing-profile-name>
```

This merely resolves the platform-specific installed official executable;
the normal lifecycle validates the supplied profile and invokes the official
`doctor` before registering the user-level task/unit. Existing registrations
are not replaced without the existing explicit replacement authorization.
The option rejects duplicate or mixed `--tunnel-client-bin` selection;
there is no fallback to a system-global binary or implicit download.
A packaged binary is not proof against a same-principal file replacement,
and installed service custody must still satisfy the platform-specific gates.

Installation does **not** provision authentication, auto-create a tunnel,
modify Scheduled Tasks/systemd units or restart a running client. The existing
`jdc tunnel install --tunnel-client-bin <absolute-path> ...` and Linux lifecycle
commands may target this executable explicitly. A future user-facing guided
onboarding flow requires its own acceptance and security review; shipping this
binary alone does not implement that flow. The active Windows host should
transition only through a separately verified, reversible service cutover.

Verification of release SHA-256 establishes correspondence with the pinned
GitHub artifact, **not** independent publisher signature/provenance validation.
The current non-release candidates remain unsigned and fail closed for
missing/unverified downloads. Release approval still requires independently
verified provenance, full installer acceptance and all P0 gates below.

## Production release gate

The only approved release version/tag publisher is the existing
.github/workflows/release.yml invoking googleapis/release-please-action.
It requires explicit owner approval and closure of P0 security blockers
#124, #139 and #148, Linux runtime/installer acceptance #150, and secure local
operations and credential recovery #248. Candidate workflows cannot override
these release-readiness requirements.

Installer artifacts currently carry UNPUBLISHED filenames, are not signed,
are retained only as short-lived GitHub Actions artifacts, and must not be
uploaded to the public GitHub Releases page as a stable release. A future
release-asset publishing workflow must first supply authenticated Windows
code signing, artifact provenance/attestations, final SHA-256 checksums,
independent install/uninstall acceptance and an explicit approval gate.

## Constraints

Never include native/capability-probe or the privileged broker in these
candidates while FFI and object-isolation findings are unresolved. Do not
run the existing npm postinstall lifecycle in this packaging path. The
installer is a CLI/MCP server; installation does not auto-connect it to
ChatGPT or other MCP clients. Existing server configuration and services
must remain unchanged during acceptance.
