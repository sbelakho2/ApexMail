# Changelog

All notable changes to the ApexMail PHP SDK will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-03-11

### Added

- Initial stable release of the ApexMail PHP SDK (requires PHP 8.1+).
- `ApexMail\Client` with configurable base URL, timeout, and retry policy.
- `$client->emails` resource — `send`, `batch`, `get`, `list`.
- `$client->domains` resource — `create`, `list`, `get`, `verify`, `delete`.
- `$client->webhooks` resource — `create`, `list`, `get`, `update` (PATCH), `delete`.
- `$client->templates` resource — `create`, `list`, `get`, `getBySlug`, `update` (PUT), `delete`, `duplicate`, `rollback`, `render`.
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

## [1.0.1] — 2026-05-14

### Added

- Cursor-based pagination support on `list()` methods: `cursor` parameter added to `Emails`, `Templates`, `Events`, and `Suppressions`.
- `tag` filter on `Suppressions.list()`.
- `test()` method on `Webhooks` resource.
