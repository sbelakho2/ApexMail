# Changelog

All notable changes to the ApexMail PHP SDK will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Template sends.** `$client->emails->send()` accepts `template_id` +
  `template_data`: the stored template supplies subject/html/text, rendered
  with the supplied variables, and a template-only send may omit
  `subject`/`html`/`text`. An explicit `subject`/`html`/`text` overrides the
  rendered field. `template_data` without `template_id` (or a list-shaped
  `template_data`) is refused client-side, naming the contract.

## [1.0.0] — 2026-03-11

### Added

- Initial stable release of the ApexMail PHP SDK (requires PHP 8.1+).
- `ApexMail\Client` with configurable base URL, timeout, and retry policy.
- `$client->emails` resource — `send`, `batch`, `get`, `list`.
- `$client->domains` resource — `create`, `list`, `get`, `verify`, `delete`.
- `$client->webhooks` resource — `create`, `list`, `get`, `update` (PATCH), `delete`.
- `$client->templates` resource — `create`, `list`, `get`, `update` (PUT), `delete`, `duplicate`, `rollback`, `render`.
- `$client->suppressions` resource — `add`, `list`, `check`, `delete`, `bulk`.
- `$client->events` resource — `list`, `getByMessage`, `get`, `stats`, `timeseries`.
- `$client->analytics` resource — `get` with date range, grouping, tag, and domain filters.
- `$client->apiKeys` resource — `create`, `list`, `revoke`.
- `Client::verifyWebhookSignature` helper for inbound webhook verification.
- Automatic retries with exponential backoff (max 3, 500 ms initial, 5 s cap).
- Idempotency key support.
- Response size limiting (20 MB max) via streaming cURL write callback.
- Structured exception hierarchy for authentication, validation, and rate-limiting failures.
- Retry-After header parsing (integer seconds and HTTP-date).
- Strict types enforced throughout.
- Redacted API key in `__toString` for safe logging.

## [Unreleased]

### Fixed

- **Live envelope unwrap (SDK-PHP-1).** The api-server success envelope always
  serialises `"error": null`, and `isset()` is false for JSON null — the old
  `decodeResponseBody()` guard therefore returned the raw envelope instead of
  `data` for every single-object response. `emails->send()` (and `get`,
  `batch`, `analytics->dashboard/volume/engagement/deliverability/export/
  analyzeSubjectLine`) now unwrap correctly; error bodies are still passed
  through whole so `throwApiError()` keeps its code/message.
  Regression tests: `tests/EnvelopeAndSurfaceTest.php`,
  `test.php` stub `error: null` envelopes.

### Added

- `Emails::cancel($id)` → `POST /v1/messages/:id/cancel` (mounted in
  messages.rs; implemented by the Python/Ruby/Java SDKs and documented as
  `emails.cancel(id)` in docs/api/sdk-reference.md).
- `Webhooks::rotateSecret($id)` → `POST /v1/webhooks/:id/rotate-secret`.

### Corrected

- The 1.0.0 entry listed a `getBySlug` templates method; the API has no
  by-slug route and the method never existed — removed from the record.

## [1.0.1] — 2026-05-14

### Added

- Cursor-based pagination support on `list()` methods: `cursor` parameter added to `Emails`, `Templates`, `Events`, and `Suppressions`.
- `test()` method on `Webhooks` resource.
