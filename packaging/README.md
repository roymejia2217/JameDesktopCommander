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

## Production release gate

The only approved release version/tag publisher is the existing
.github/workflows/release.yml invoking googleapis/release-please-action.
It currently requires owner approval plus closed security blockers #124,
#139 and #148; the candidate workflow cannot remove or override that gate.

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
