# Changelog

All notable changes to the ApexMail Go SDK will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

### Fixed

- **Critical (GO-1):** mutating POSTs now send `Idempotency-Key`. The SDK sent
  the historical `X-Idempotency-Key` spelling, which the server ignores
  (`middleware/idempotency.rs` reads exactly `idempotency-key`), so automatic
  and caller-supplied keys never reached the deduplication ledger and a
  retried send could double-enqueue. The tests asserting the wrong header
  were corrected to the real spelling and now also assert the legacy header
  never reaches the wire.
- **Response shapes:** `Events.List`/`Events.GetByMessage` and
  `APIKeys.List` now decode the API's bare arrays; `Events.Get` decodes the
  flat `EventResponse` (the `{"event": …}` wrapper no route produces is
  gone); `Events.Timeseries` returns `[]TimeseriesPoint`; and
  `Analytics.Volume` returns `[]VolumePoint` (an array inside the envelope —
  previously every successful call failed to parse).
- **Pagination:** `Emails.List` captures the envelope `meta`
  (`hasMore`/`nextCursor`) into `Pagination`, exposed via `HasMore()` and
  `NextCursor()`.
- **Query contract:** a client-supplied `cursor` is rejected client-side on
  `/v1/templates`, `/v1/suppressions`, `/v1/events` and `/v1/auth/api-keys`
  (those server queries are `deny_unknown_fields` without a cursor and answer
  a plain-text 400); the events list filters now send the accepted
  `event_type`/`message_id` names, and `EventAggregateOptions` carries the
  accepted `{From, To}` only for `/stats` and `/timeseries`.
- **Send payload:** `template_id`/`template_data` are no longer serialized
  (the server always answers 422 for them); setting either fails client-side
  with an error naming the contract.
- **Errors:** `RateLimitError` now exposes `RetryAfter` (parsed from the
  `Retry-After` header, integer seconds or HTTP-date).
- **Domains:** added `Domains.DNSRecords` (`GET /v1/domains/:id/dns-records`)
  and `Domains.AuthStatus` (`GET /v1/domains/:id/auth-status`).
- **Tests:** every fixture that encoded a payload no route produces was
  rebuilt from the Rust handlers, and an env-gated live-stack contract test
  (`APEXMAIL_LIVE_API_KEY`/`APEXMAIL_LIVE_BASE_URL`) drives the fixed
  surfaces against a running api-server.

### Breaking changes

- `APIKeys.List` returns `[]APIKeyInfo`, `Events.Get` returns `*Event`,
  `Events.Timeseries` returns `[]TimeseriesPoint`, and `Analytics.Volume`
  returns `[]VolumePoint` — the previous return types could not decode the
  API's own responses.
- `Event` fields now use the server's snake_case payload names:
  `message_id`, `event_type`, `recipient`.
- `EventAggregateOptions` no longer carries the rejected
  `Type`/`MessageID`/`DomainID`/`Start`/`End`/`Interval` filters.

## [1.0.0] — 2026-03-11

### Added

- Initial stable release of the ApexMail Go SDK.
- `Client` with configurable base URL, timeout, and retry policy.
- `Emails` resource — `Send`, `Batch` (up to 1000), `Get`, `List`, `Cancel`.
- `Domains` resource — `Create`, `Get`, `List`, `Verify`, `Delete`, `Health`.
- `Webhooks` resource — `Create`, `List`, `Get`, `Update` (PUT), `Delete`, `Test`, `RotateSecret`.
- `Templates` resource — `Create`, `Get`, `List`, `Update` (PUT), `Delete`, `Duplicate`, `Rollback`, `Render`.
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

- Cursor-based pagination support for `Emails.List`: the `Cursor` field on
  `ListEmailsOptions` and the captured `Pagination` meta (`Cursor`,
  `HasMore`). `GET /v1/messages` is the only list route that accepts a
  `cursor` query parameter; the other list options keep the field for source
  compatibility but reject it client-side because their server queries are
  `deny_unknown_fields` without a cursor.

### Deprecated

- `ListSuppressionsOptions.Tag` — never accepted by the API (the server
  query is `{limit, offset, reason}`); the field is retained for
  source compatibility but is not sent. Suppressions can be filtered by
  `Reason` only.
