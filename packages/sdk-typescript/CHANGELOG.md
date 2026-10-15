# Changelog

All notable changes to the ApexMail Node.js/TypeScript SDK will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.1] — 2026-10-15

### Added

- Initial release of the ApexMail Node.js/TypeScript SDK (`@apexmail/node`), on
  the same lockstep version as the other first-party SDKs.
- `ApexMail` client with configurable base URL, timeout, retries,
  response-size cap and cancellation signal; ESM + CommonJS builds with type
  declarations; zero runtime dependencies (Node >= 20).
- `client.emails` — `send`, `batch`, `sendBatch` (alias), `get`, `list`
  (cursor pagination via the envelope's `meta.nextCursor`/`meta.hasMore`),
  `cancel`.
- `client.domains` — `create`, `list`, `get`, `verify`, `delete`, `health`.
- `client.templates` — `create`, `list`, `get`, `update`, `duplicate`,
  `rollback`, `delete`, `render`.
- `client.suppressions` — `create`/`add`, `list`, `delete`, `check`, `bulk`.
- `client.events` — `list`, `getByMessage`, `get`, `stats`, `timeseries`.
- `client.webhooks` — `create`, `list`, `get`, `update`, `delete`, `test`,
  `rotateSecret`.
- `client.analytics` — `dashboard`, `volume`, `engagement`, `deliverability`,
  `analyzeSubjectLine`, `export`, deprecated `get` alias.
- `client.apiKeys` — `create`, `list`, `revoke`.
- Full TypeScript types for every request/response; the send-payload builder
  serializes every accepted option (display names preserved as "Name <addr>",
  tags flattened, snake_case wire fields) per the shared
  `packages/contract/send-contract.json` fixture.
- Automatic retries with bounded quadratic backoff and ±20% jitter on
  `408/429/500/502/503/504`; Retry-After honored in full, capped at 120 s;
  90 s total retry budget.
- Automatic per-operation `Idempotency-Key` generation for mutating POSTs
  (caller-supplied keys honored; control characters stripped; 128-char cap).
- Structured exception hierarchy (`ApexMailError`, `ValidationError`,
  `AuthenticationError`, `ForbiddenError`, `NotFoundError`, `ConflictError`,
  `RateLimitError` with `retryAfter`, `ServerError`), each carrying `code`,
  `statusCode` and the server's `requestId`.
- Webhook signature verification (`verifySignature` /
  `verifyWebhookSignature`) matching the platform scheme exactly:
  HMAC-SHA256 over `"{timestamp}.{payload}"` with the
  `X-ApexMail-Signature: sha256=<hex>` and `X-ApexMail-Timestamp:
  <milliseconds>` headers, constant-time comparison, 300 s tolerance
  (configurable), legacy `t=..,v1=..` headers accepted.
- HTTPS enforcement (HTTP only for localhost), API-key format validation and
  masked `toString()`/inspect output.
- Browser-secret protection: the client refuses to construct in a
  browser-like environment, where an embedded API key would be public.
- `node:test` contract suite covering payload shapes against the shared
  fixture, auth headers, retries, idempotency, error mapping, the response
  cap, cancellation and webhook verification — wired into CI as a REQUIRED
  lane gated by `CI_SDK_CHECK`.
