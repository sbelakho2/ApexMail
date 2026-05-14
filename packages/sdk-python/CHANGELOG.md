# Changelog

All notable changes to the ApexMail Python SDK will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-03-11

### Added

- Initial stable release of the ApexMail Python SDK.
- `ApexMail` synchronous client with configurable base URL, timeout, and retry policy.
- `AsyncApexMail` asynchronous client with identical API surface.
- `client.emails` resource — `send`, `batch`, `get`, `list`, `cancel`.
- `client.domains` resource — `create`, `list`, `get`, `verify`, `delete`.
- `client.templates` resource — `create`, `list`, `get`, `get_by_slug`, `update` (PUT), `delete`, `duplicate`, `rollback`, `render`.
- `client.suppressions` resource — `create`, `add`, `list`, `delete`, `check`, `bulk`.
- `client.events` resource — `list`, `get_by_message`, `get`, `stats`, `timeseries`.
- `client.webhooks` resource — `create`, `list`, `get`, `update`, `delete`.
- `client.analytics` resource — `get` with date range, grouping, tag, and domain filters.
- `client.api_keys` resource — `create`, `list`, `revoke`.
- Full type hints with Pydantic v2 models for all request/response types.
- Automatic retries with exponential backoff (max 3, 500 ms initial, 5 s cap, 90 s total timeout).
- Idempotency key support.
- HTTPS enforcement (HTTP only allowed for localhost).
- Masked API key in `__repr__` to prevent accidental credential logging.
- `httpx`-based HTTP transport.
- Response size limiting (20 MB max).
- Structured exception hierarchy for authentication, validation, and rate-limiting failures.
- Retry-After header parsing (seconds and HTTP-date).
- Webhook signature verification (`verify_webhook_signature`).

## [1.0.1] — 2026-05-14

### Added

- Cursor-based pagination support: `cursor` and `has_more` fields added to `TemplateListResponse`, `SuppressionListResponse`, and `EventListResponse` models.
