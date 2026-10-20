# T011-C — XLSX processing from authorized bytes (non-shipping)

**Issue:** [#139](https://github.com/roymejia2217/JameDesktopCommander/issues/139).
**Baseline:** `9ba0a9a73904fd2d7d676814d18e165d2e02b851`. **Status:** isolated internal parsing seam; not a production confinement fix.

The existing `ExcelFileHandler.read(path, options)` continues using the
documented ExcelJS pathname API and the original metadata/stat checks.
The new `ExcelFileHandler.readBytes(Uint8Array, options, displayName?)`
uses ExcelJS's documented `workbook.xlsx.read(stream)` API with a
Node.js in-memory Readable; this avoids the library's legacy Buffer
TypeScript declaration mismatch without casts or altered dependencies.
It shares the legacy formatting and pagination method. A caller-provided
display label affects only returned text; it is not used to authorize,
resolve or open a file.

In-memory processing accepts Node `Buffer`, ordinary `Uint8Array`, and
sliced byte views. Bytes are copied to a fresh Buffer before ExcelJS
streaming so the parser sees only the supplied window. The XLSX
reader still aggregates the stream internally before ZIP parsing; this
does not make the parser streaming or memory-bounded. Path strings,
missing inputs and compressed workbooks larger than the existing
10 MiB limit are rejected before parsing. Unit tests cover workbook
metadata, secondary-sheet/range pagination, view boundaries, malformed
inputs and byte-for-byte output parity against the legacy reader.

**Security limitations:**

- Compressed input size is *not* an expanded ZIP/memory or CPU work
  ceiling. ExcelJS can allocate unbounded in-memory worksheet and
  shared-string models from relatively small archives. A separately
  maintained and proven ZIP expansion / sheet-row / cell-value bound,
  or a documented restricted-mode denial, is required before production
  native-capability routing.
- No operation here obtains a verified root, handles policy revocation,
  enforces cancellation or performs a confined write. The filename
  reader, `write`, `editRange`, and `getInfo` still use path APIs.
- This seam cannot be advertised as confined filesystem access or
  connected to production MCP handlers until N-API ownership #124 and
  end-to-end T011-C/D/E are independently accepted. Privileged SCM #80
  remains entirely separate.
- Only XLSX ZIP parsing is exercised here. Existing extension recognition
  includes XLS/XLSM, but this change is **not** a claim of full XLS support.

**Release gate:** NO CHANGE. Experimental byte input only.
