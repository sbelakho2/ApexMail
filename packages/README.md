# ApexMail SDK Packages

This directory contains official ApexMail SDK packages for various languages:

| Language | Package | Status | Maintainer |
|----------|---------|--------|------------|
| Go | `packages/sdk-go/` | ✅ Active | ApexMail Team |
| Ruby | `packages/sdk-ruby/` | ✅ Active | ApexMail Team |
| Java | `packages/sdk-java/` | ✅ Available | ApexMail Team |
| Python | `packages/sdk-python/` | ✅ Available | ApexMail Team |
| PHP | `packages/sdk-php/` | ✅ Available | ApexMail Team |
| Rust | (planned) | 🔄 Planned | ApexMail Team |

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

All SDKs now support cursor-based pagination for list endpoints (messages, templates, events, suppressions).
The `Pagination` struct in each SDK includes `cursor` (string, for the next page token) and `has_more` (boolean)
fields. See each SDK's CHANGELOG for details:

- **Go SDK:** `ListEmailsOptions.Cursor`, `ListTemplatesOptions.Cursor`, `ListSuppressionsOptions.Cursor`, `ListEventsOptions.Cursor`
- **Java SDK:** Cursor parameter in all list methods via `Map` options
- **PHP SDK:** `$options['cursor']` in all list methods
- **Python SDK:** `cursor=` keyword argument in all list methods
- **Ruby SDK:** `cursor:` keyword argument in all list methods

SDK clients should return typed error objects with `Code` and `Message` fields.
