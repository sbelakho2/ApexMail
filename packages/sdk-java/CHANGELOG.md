# Changelog

All notable changes to the ApexMail Java SDK will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **`analytics().volume()` could not parse its own response (SDK-JAVA-2).**
  The live payload is a bare array inside the envelope's `data`
  (`[{date, sent, delivered, bounced}, …]`); the previous
  `Map<String, Object>` signature made every successful call fail with
  PARSE_ERROR. It now returns `List<Map<String, Object>>`.
- Plain-text error bodies (e.g. axum's 400 for a malformed query parameter)
  now surface their synthetic `code` instead of dropping it to null.
- README examples referenced types that do not exist
  (`Emails.GetResponse` as the return of `get()`, `Domains.CreateResponse`,
  `Domains.ListResponse`, `Domains.HealthResponse`,
  `Webhooks.WebhookResponse`, `Webhooks.WebhookListResponse`); rewritten
  against the real signatures.

### Added

- `LiveStackContractTest` — an env-gated (`APEXMAIL_LIVE_API_KEY`) live-stack
  contract test covering every resource method, envelope unwrap,
  idempotency replay and typed errors.

### Corrected

- The 1.0.0 entry listed a `getBySlug` templates method; the API has no
  by-slug route and the method never existed — removed from the record.

## [1.0.1] — 2026-05-14

### Added

- Cursor-based pagination support: `cursor` accepted in the options `Map` of
  every list method (`emails().list`, `templates().list`, `suppressions().list`,
  `events().list`), forwarded as the `cursor` query parameter.

## [1.0.0] — 2026-03-11

### Added

- Initial stable release of the ApexMail Java SDK.
- `ApexMailClient` with configurable base URL, timeout, and retry policy (implements `AutoCloseable`).
- `emails()` resource — `send`, `batch`, `get`, `list`, `cancel`.
- `domains()` resource — `create`, `list`, `get`, `verify`, `delete`, `health`.
- `webhooks()` resource — `create`, `list`, `get`, `update` (PATCH), `delete`, `test`.
- `templates()` resource — `create`, `list`, `get`, `update` (PUT), `delete`, `duplicate`, `rollback`, `render`.
- `suppressions()` resource — `add`, `list`, `check`, `delete`.
- `events()` resource — `list`, `getByMessage`, `get`, `stats`, `timeseries`.
- `analytics()` resource — `get` with date range, grouping, tag, and domain filters.
- `apiKeys()` resource — `create`, `list`, `revoke`.
- Type-safe request builders using Java records.
- HTTP/2 support via `java.net.http.HttpClient`.
- Automatic retries with exponential backoff (max 3, 500 ms initial, 5 s cap).
- Idempotency key support.
- Jackson JSON serialization with JavaTime module.
- Response size limiting (20 MB max).
- Structured exception hierarchy for authentication, validation, and rate-limiting failures.
- Retry-After header parsing (seconds and HTTP-date).
- Resource cleanup via `AutoCloseable`.
- Webhook signature verification (`verifyWebhookSignature`).
- API key validation on client construction.

### Fixed

- Template update now uses `PUT` (full replacement) instead of `PATCH` (partial update), matching OpenAPI spec.
- Webhook update now uses `PATCH` to match OpenAPI spec.
- Suppressions list supports `reason`, `tag`, `cursor`, `limit`, `offset` filters via options map.
- Events list supports `type`, `messageId`, `domainId`, `start`, `end`, `cursor`, `limit`, `offset` filters.
