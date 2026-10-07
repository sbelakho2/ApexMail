# ApexMail SDK Packages

This directory contains official ApexMail SDK packages for various languages:

| Language | Package | Version | Status | Maintainer |
|----------|---------|---------|--------|------------|
| Go | `packages/sdk-go/` | 1.0.1 | ✅ Active | ApexMail Team |
| Ruby | `packages/sdk-ruby/` | 1.0.1 | ✅ Active | ApexMail Team |
| Java | `packages/sdk-java/` | 1.0.1 | ✅ Available | ApexMail Team |
| Python | `packages/sdk-python/` | 1.0.1 | ✅ Available | ApexMail Team |
| PHP | `packages/sdk-php/` | 1.0.1 | ✅ Available | ApexMail Team |
| Rust | (planned) | — | 🔄 Planned | ApexMail Team |

All five SDKs are released in lockstep at the same version. Each SDK's
version constant (Go `sdkVersion`, Python `__version__`/`pyproject.toml`,
Ruby `SDK_VERSION`/gemspec, Java `ApexMailClient.SDK_VERSION`, PHP
`Client::SDK_VERSION`) must equal the head entry of its `CHANGELOG.md`.
`python3 packages/check_versions.py` enforces this mechanically (exit 1 on
drift) and is the CI gate for the invariant (audit SM15 F4).

## Rust SDK

A native Rust SDK (`apexmail-sdk`) is planned. Since the entire ApexMail backend is written in Rust,
a Rust SDK will be the most performant option, allowing direct reuse of types and serialization.
Track progress at [GitHub Issues](https://github.com/apexmail/apexmail/issues).

## Error Handling

All SDKs should parse the standard ApexMail API error envelope:
```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Too many requests. Please retry after 60 seconds."
  }
}
```

## Cursor Pagination

Only `GET /v1/messages` supports cursor-based pagination. Its response
envelope carries `meta.hasMore` / `meta.nextCursor`, and the SDKs capture
that metadata on the list response.

The other list endpoints (templates, suppressions, events, API keys) do NOT
accept a `cursor` query parameter — their server query structs are
`deny_unknown_fields` without one, and sending it produces a plain-text
HTTP 400 (`Failed to deserialize query string …`). Every SDK therefore
implements the following contract:

- **Go SDK:** `Cursor` on `ListEmailsOptions` is forwarded; the
  `ListTemplatesOptions`/`ListSuppressionsOptions`/`ListEventsOptions`/
  `ListAPIKeysOptions` `Cursor` fields are rejected client-side with an
  error naming the endpoint. `ListEmailsResponse.Pagination` exposes the
  captured `Cursor`/`HasMore` (plus `NextCursor()`/`HasMore()` accessors).
- **Java SDK:** the messages list options `Map` forwards `cursor`; the other
  list methods throw when a `cursor` key is passed.
- **PHP SDK:** `$options['cursor']` is forwarded on messages only; the other
  list methods throw an `InvalidArgumentException` for `cursor`, and the
  messages envelope metadata (`has_more`, `next_cursor`) is captured on the
  client.
- **Python SDK:** `cursor=` is forwarded on messages only; the other list
  methods raise for `cursor`, and list models expose `cursor`/`has_more`.
- **Ruby SDK:** `cursor:` is forwarded on messages only; the other list
  methods raise `ArgumentError` for `cursor`.

SDK clients should return typed error objects with `Code` and `Message` fields.
