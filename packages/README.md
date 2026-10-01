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

All SDKs support cursor-based pagination for list endpoints (messages, templates, events, suppressions).
Every list method accepts a `cursor` parameter that is forwarded as the `cursor` query parameter.
See each SDK's CHANGELOG for details:

- **Go SDK:** `Cursor` field on `ListEmailsOptions`, `ListTemplatesOptions`, `ListSuppressionsOptions`, `ListEventsOptions`; `Pagination` exposes `Cursor` and `HasMore`
- **Java SDK:** `cursor` key in the options `Map` of every list method
- **PHP SDK:** `$options['cursor']` in all list methods; envelope metadata (`has_more`, `next_cursor`) is captured on the client
- **Python SDK:** `cursor=` keyword argument in all list methods; list models expose `cursor`/`has_more`
- **Ruby SDK:** `cursor:` keyword argument in all list methods

SDK clients should return typed error objects with `Code` and `Message` fields.
