# Changelog

All notable changes to the ApexMail Java SDK will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-03-11

### Added

- Initial stable release of the ApexMail Java SDK.
- `ApexMailClient` with configurable base URL, timeout, and retry policy (implements `AutoCloseable`).
- `emails()` resource — `send`, `batch`, `get`, `list`.
- `domains()` resource — `create`, `list`, `get`, `verify`, `delete`, `health`.
- `webhooks()` resource — `create`, `list`, `get`, `update`, `delete`.
- `templates()` resource — `create`, `list`, `get`, `getBySlug`, `update`, `delete`, `render`, `validateReactEmail`, `reactEmailStarter`.
- `suppressions()` resource — `add`, `list`, `check`, `delete`.
- `events()` resource — `list`, `getByMessage`, `get`.
- Type-safe request builders using Java records.
- HTTP/2 support via `java.net.http.HttpClient`.
- Automatic retries with exponential backoff (max 3, 500 ms initial, 5 s cap).
- Idempotency key support.
- Jackson JSON serialization with JavaTime module.
- Response size limiting (20 MB max).
- Structured exception hierarchy for authentication, validation, and rate-limiting failures.
- Retry-After header parsing (seconds and HTTP-date).
- Resource cleanup via `AutoCloseable`.
