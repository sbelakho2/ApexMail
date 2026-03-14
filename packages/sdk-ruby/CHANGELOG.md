# Changelog

All notable changes to the ApexMail Ruby SDK will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-03-11

### Added

- Initial stable release of the ApexMail Ruby SDK (requires Ruby 3.0+).
- `ApexMail::Client` with configurable base URL, timeout, and retry policy.
- `client.emails` resource — `send_email`, `batch`, `get`, `list`.
- `client.domains` resource — `create`, `list`, `get`, `verify`, `delete`, `health`.
- `client.webhooks` resource — `create`, `list`, `get`, `update`, `delete`.
- `client.templates` resource — `create`, `list`, `get`, `get_by_slug`, `update`, `delete`, `render`, `validate_react_email`, `react_email_starter`.
- `client.suppressions` resource — `add`, `list`, `check`, `delete`.
- `client.events` resource — `list`, `get_by_message`, `get`.
- `client.analytics` resource — `get` with date range, grouping, and tag filters.
- `client.api_keys` resource — `create`, `list`, `revoke`.
- Automatic retries with exponential backoff (max 3, 500 ms initial, 5 s cap).
- Idempotency key support.
- Keep-alive connection management with timeout resets.
- SSL peer verification enabled by default.
- Response size limiting (20 MB max) via streaming body read.
- Structured error handling with distinct types for authentication, validation, and rate-limiting failures.
- Retry-After header parsing (seconds and HTTP-date).
- Zero external dependencies (stdlib only).
