# Changelog

All notable changes to the ApexMail Go SDK will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-03-11

### Added

- Initial stable release of the ApexMail Go SDK.
- `Client` with configurable base URL, timeout, and retry policy.
- `Emails` resource — `Send`, `Batch` (up to 1000), `Get`, `List`, `Cancel`.
- `Domains` resource — `Create`, `Get`, `List`, `Verify`, `Delete`, `Health`.
- `Webhooks` resource — `Create`, `List`, `Get`, `Update` (PATCH), `Delete`, `Test`.
- `Templates` resource — `Create`, `Get`, `GetBySlug`, `List`, `Update` (PUT), `Delete`, `Duplicate`, `Rollback`, `Render`.
- `Suppressions` resource — `Add`, `List`, `Check`, `Delete`, `Bulk`.
- `Events` resource — `List`, `GetByMessage`, `Get`, `Stats`, `Timeseries`.
- `Analytics` resource — `Get` with `from`, `to`, `groupBy`, `tag`, `domain` filters.
- `APIKeys` resource — `Create`, `List`, `Revoke`.
- `VerifyWebhookSignature` helper for inbound webhook verification.
- Automatic retries with exponential backoff (max 3, 500 ms initial, 5 s cap).
- Idempotency key support via request options.
- Context-aware methods (`context.Context` on every call).
- Connection pooling with tuned HTTP transport.
- Response size limiting (20 MB max).
- Email address validation helper.
- Structured error handling with distinct types for authentication, validation, and rate-limiting failures.
- Retry-After header parsing (seconds and RFC 1123 date formats).
- Zero external dependencies (stdlib only).

## [1.0.1] - 2026-05-14

### Added

- Cursor-based pagination support: `Cursor` field added to `Pagination` struct and all list options (`ListEmailsOptions`, `ListTemplatesOptions`, `ListSuppressionsOptions`, `ListEventsOptions`).
- `Tag` filter on `ListSuppressionsOptions` for filtering suppressions by tag.
