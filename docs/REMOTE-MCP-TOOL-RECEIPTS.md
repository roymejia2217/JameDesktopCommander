# Remote MCP tool-call stage receipts

**Scope:** privacy-preserving **local stdout telemetry**, not an endpoint,
health guarantee, distributed trace or automated recovery controller.

Remote Device tool calls emit a new random per-call receipt ID, a fixed
allowlisted stage and monotonic elapsed milliseconds. Receipts intentionally
exclude command arguments, tool results, metadata, device IDs, credentials and
server call IDs. Only the local Remote Device can correlate its own receipt
across stages; IDs are not interoperable with server-side request IDs.

| Stage | Meaning |
| --- | --- |
| `received` | Device-side callback received a call targeted to this instance |
| `duplicate_ignored` / `claim_rejected` | Call was not executed |
| `claimed` | Remote call claim accepted |
| `local_completed` | Local MCP tool returned, before result publication |
| `result_published` | Result update operation completed without an error |
| `execution_failed` | Local execution or prior reporting operation failed |
| `failure_published` | Failure update completed without an error |
| `result_publish_failed` | Failure update operation could not be completed |

A missing `received` event does not prove that the upstream provider failed;
logs may be absent, buffered, rotated, or inaccessible. A returned
`result_published` does not prove delivery to a ChatGPT UI. Correlation of
upstream requests requires separate, privacy-reviewed provider evidence.

The client SDK, Remote Channel and local MCP server remain operationally
unchanged. No watchdog, timer, scheduled task, installer or retry policy is
introduced. The existing server-side error telemetry is not replaced by
these receipts and requires its own privacy/security review.

Acceptance: focused receipt-format tests, hosted CI, CodeQL and controlled
isolated runtime verification. See issue #98 for the unresolved
end-to-end remote delivery incident. No production restart is authorized.
