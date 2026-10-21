# Portable candidate integrity doctor

The unpublished portable candidate supports `portable doctor` from the
bundled Node.js executable and compiled `dist/index.js`.

The command checks the target platform, candidate schema, expected
non-release status, Node.js version, complete SHA-256 file inventory,
missing and extra files, symlinks, case-folded collisions, and build
provenance. It reads files only and never installs services.

This diagnostic establishes internal consistency, **not publisher
authenticity**. A separate externally trusted release signature, provenance
and published digest are required before production distribution.
The candidate remains `releaseEligible: false`.

The existing GitHub portable workflow runs this command from the
independently restored artifact before its real MCP SDK test. Synthetic
unit fixtures exercise normal operation and failure cases.
