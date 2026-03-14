# Changelog

All notable changes to the ApexMail Node.js SDK will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-03-11

### Added

- Initial stable release of `@apexmail/node`.
- `ApexMail` client with automatic retry and timeout configuration.
- `emails.send()` — send transactional emails with HTML/text/template bodies.
- `emails.sendBatch()` — send up to 100 emails in a single API call.
- Full TypeScript type definitions with strict mode support.
- Configurable base URL for self-hosted deployments.
- Idempotency key support via `Idempotency-Key` header.
- Structured error handling with distinct types for authentication, validation, and rate-limiting failures.
