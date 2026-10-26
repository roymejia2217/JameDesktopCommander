# T011-C PDF byte operations: non-shipping integration seam

**Issue:** [#139](https://github.com/roymejia2217/JameDesktopCommander/issues/139).
**Base:** `9ba0a9a73904fd2d7d676814d18e165d2e02b851`.
**Status:** Byte-oriented PDF processing seam only; **not a production security fix**.

The existing pathname/URL `parsePdfToMarkdown` and pathname-based `editPdf`
remain supported and unchanged. New `parsePdfBytesToMarkdown(bytes, pages)`
and `editPdfBytes(bytes, operations)` consume supplied `Uint8Array` values.
The byte editing API accepts only page deletion and page insertion with a
second authorized PDF byte value. Unlike the legacy editor, it accepts no
pathname, Markdown, URL, Puppeteer input or filesystem write destination.

This is deliberately narrower than the existing PDF tool:
- The caller must obtain both the original PDF and every insert source through
  separately verified capabilities, applying bounded read and cancellation.
- All transformations occur in memory; callers must perform final writes via
  an independently confined, appropriately committed byte-write operation.
- There is no fallback from the byte APIs to filename access, including for
  nested insert sources; accidental `sourcePdfPath` or `markdown` inputs are
  rejected rather than reinterpreted.
- `editPdfBytes` reuses existing `deletePages` and `insertPages` algorithms,
  preserving the same page-index behavior and `pdf-lib` serialization.
- No MCP handler consumes these new functions yet. Existing `write_pdf`,
  `read_file`, format handlers and PDF image/Markdown secondary resources
  still require T011-C integration and adversarial Windows/Linux acceptance.

The unit tests are memory-only and are selected by the existing `test/test*.js`
Node test convention. They verify valid parsing, deletion, insertion, source
byte preservation and rejection of pathname substitutes and malformed input.
They **do not** prove N-API safety, races, final write atomicity, search
containment, native handle ownership or package-level authorization.
See [the parent T011 contract](T011-FILESYSTEM-CAPABILITY-BOUNDARY.md).

**Release gate:** unchanged; #124, #139 and #80 remain blockers.
