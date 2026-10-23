# T011-C DOCX byte reader (non-shipping)

**Issue:** [#139](https://github.com/roymejia2217/JameDesktopCommander/issues/139).
**Baseline:** `9ba0a9a73904fd2d7d676814d18e165d2e02b851`.
**Status:** Internal byte-processing seam; not an authorization fix.

The existing `DocxFileHandler.read(path, options)` now calls
`readDocxBytes(Uint8Array, options)` after its original `fs.readFile`.
The newly exposed byte-only reader uses the same `PizZip`,
`loadDocxZip`, outline extraction, XML pagination and metadata logic.
This keeps existing file-handler behavior stable while allowing a future
capability-bound caller to supply bytes without passing a filename to the
DOCX parser.

**Security and resource limits:** The byte reader does not open paths and
rejects string paths. It is *not* a security sandbox: the caller must verify
native capability authorization, enforce a compressed-size limit and bounded
ZIP expansion, control cancellation and constrain work/memory. In particular,
the reader still decompresses and formats XML in memory. A small compressed
DOCX may expand substantially; a bound on compressed bytes alone is
insufficient. T011 requires a separately reviewed bound on decompression and
document XML size before production routing.

Existing DOCX editing and writing still reopen pathnames, and are outside
this narrow change. T011-C/D/E remain blocked along with #124 and #80.
No native addon, MCP routing, SCM or runtime installation changes occur.

Tests use a generated in-memory ZIP, verify outline and XML pagination, reject
filename and malformed inputs, and compare both output modes against the
unchanged legacy path-handler behavior using a disposable test directory.
