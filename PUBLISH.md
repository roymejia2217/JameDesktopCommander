# Release Guide

JameDesktopCommander uses Release Please for version proposals, tags, and GitHub Releases.
Manual version bumps, direct pushes to `main`, and hand-created release tags are not supported.

## Release flow

1. Merge governed feature and fix pull requests into `main` using squash merge.
2. Release Please evaluates the Conventional Commit squash history and creates or updates its
   canonical release pull request.
3. The release pull request must pass `PR Governance`, `Required CI`, and CodeQL just like any
   other change.
4. Merge the release pull request with squash merge.
5. Release Please creates the immutable `vX.Y.Z` tag and GitHub Release.
6. Package, MCP Registry, and MCPB publication remain disabled until JameDesktopCommander owns
   dedicated publication namespaces and the bundle metadata is rebranded away from upstream.

The release pull request title is governed as:

```text
chore(main): release X.Y.Z
```

Its body remains the native Release Please-generated body. Do not replace it with the ordinary
pull-request template.

## Release automation identity

Release Please uses a dedicated GitHub App token rather than the workflow `GITHUB_TOKEN`. This is
required so the generated release pull request triggers normal pull-request workflows.

Configure:

- `JDC_RELEASE_APP_CLIENT_ID` as a repository variable;
- `JDC_RELEASE_APP_PRIVATE_KEY` as a repository secret;
- `JDC_RELEASE_BOT_LOGIN` as the exact bot login used by the installed GitHub App.

The GitHub App should receive only the repository permissions required by the release workflow:
Contents write, Pull requests write, and Issues write.

## Publication namespaces

The fork currently inherits upstream package and MCP bundle metadata. Until JameDesktopCommander
owns its final npm, MCP Registry, and MCPB identities, the automated release pipeline creates only
the governed GitHub tag and GitHub Release. `package.json` is deliberately marked `private` as an
additional publication guard.

Do not configure the fork to publish `@wonderwhy-er/desktop-commander`,
`io.github.wonderwhy-er/desktop-commander`, or an MCPB carrying upstream ownership metadata;
those identities belong to upstream.

## Recovery

If Release Please fails after merging the release pull request, re-run the failed Release Please
workflow from the same protected `main` state. Do not delete, move, or recreate the release tag.

Release tags are protected by the `release-tag-immutability` ruleset and are not force-moved.
Artifact publication recovery will be documented only after JDC owns its publication namespaces.
