# Portable candidate integrity doctor

The unpublished portable candidate supports `portable doctor` from the
bundled Node.js executable and compiled `dist/index.js`.

The command checks the target platform, candidate schema, expected
non-release status, Node.js version, complete SHA-256 file inventory,
missing and extra files, unexpected top-level directories (including an
unapproved `native` root), symlinks, case-folded file collisions, and build
provenance. It reads files only and never installs services.
Both the independent artifact verifier and the local doctor reject undeclared
root directories, even when empty. Empty nested package directories are not
part of the file inventory; this check is not a filesystem-object confinement
or publisher-authentication guarantee.

This diagnostic establishes internal consistency, **not publisher
authenticity**. A separate externally trusted release signature, provenance
and published digest are required before production distribution.
The candidate remains `releaseEligible: false`.

The existing GitHub portable workflow runs this command from the
independently restored artifact before its real MCP SDK test. Synthetic
unit fixtures exercise normal operation and failure cases.
