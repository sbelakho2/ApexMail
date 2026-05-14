# Changelog

All notable changes to the ApexMail Ruby SDK will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-03-11

### Added

- Initial stable release of the ApexMail Ruby SDK (requires Ruby 3.0+).
- `ApexMail::Client` with configurable base URL, timeout, and retry policy.
- `client.emails` resource — `send_email`, `batch`, `get`, `list`, `cancel`.
- `client.domains` resource — `create`, `list`, `get`, `verify`, `delete`, `health`.
- `client.webhooks` resource — `create`, `list`, `get`, `update` (PATCH), `delete`.
- `client.templates` resource — `create`, `list`, `get`, `get_by_slug`, `update` (PUT), `delete`, `duplicate`, `rollback`, `render`.
- `client.suppressions` resource — `add`, `list`, `check`, `delete`, `bulk`.
- `client.events` resource — `list`, `get_by_message`, `get`, `stats`, `timeseries`.
- `client.analytics` resource — `get` with date range, grouping, tag, and domain filters.
- `client.api_keys` resource — `create`, `list`, `revoke`.
- Automatic retries with exponential backoff (max 3, 500 ms initial, 5 s cap).
- Idempotency key support.
- Keep-alive connection management with timeout resets.
- SSL peer verification enabled by default.
- Response size limiting (20 MB max) via streaming body read.
- Structured error handling with distinct types for authentication, validation, and rate-limiting failures.
- Retry-After header parsing (seconds and HTTP-date).
- Zero external dependencies (stdlib only).

## [1.0.1] — 2026-05-14

### Added

- Cursor-based pagination support: `cursor:` keyword parameter added to `EmailsAPI#list`, `TemplatesAPI#list`, `SuppressionsAPI#list`, and `EventsAPI#list`.
- `tag:` keyword parameter on `SuppressionsAPI#list` for filtering suppressions by tag.
