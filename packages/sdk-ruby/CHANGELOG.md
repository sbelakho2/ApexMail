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
- `client.templates` resource — `create`, `list`, `get`, `update` (PUT), `delete`, `duplicate`, `rollback`, `render`.
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

## [Unreleased]

### Corrected

- The 1.0.0 entry listed a `get_by_slug` templates method; the API has no
  by-slug route and the method never existed — removed from the record.
- Templates/Suppressions/Events never had server-side cursor pagination
  (their query structs are `deny_unknown_fields` and reject `cursor` with
  HTTP 400); those list methods reject `cursor` client-side with a precise
  error.

## [1.0.1] — 2026-05-14

### Added

- Cursor-based pagination support: `cursor:` keyword parameter added to `EmailsAPI#list`, `TemplatesAPI#list`, `SuppressionsAPI#list`, and `EventsAPI#list`.
