# API Versioning Strategy

> **Last updated:** 2026-06-13
> **Applies to:** All ApexMail public API endpoints

## Versioning Scheme

ApexMail uses **URL-prefix versioning** for all public API endpoints.

| Component       | Format                    | Example                        |
|-----------------|---------------------------|--------------------------------|
| Current version | `/v1/`                    | `POST /v1/messages`            |
| Base URL        | `https://api.apexmail.ee` | `https://api.apexmail.ee/v1/`  |

### Current Version: `v1`

All documented endpoints use the `/v1/` prefix. The only unversioned public endpoints are the health checks (`/health/live`, `/health/ready`, `/health/deep`), which are deliberately version-independent so monitors survive major-version transitions.

### Version Lifecycle

```
v1 (current) ──┬──> v2 (next) ──> v1 deprecated ──> v1 sunset
               │                    │                    │
               │              (announce)           (removed)
               └── stable, all new features go here first
```

## Versioning Rules

### 1. URL Prefix

Every public API endpoint MUST include the version prefix (health endpoints
excepted — they are unversioned by design):

```
✅ POST /v1/messages
✅ GET  /health/ready
❌ POST /messages             (no version — rejected)
❌ GET  /v1/health/ready      (health is not under /v1)
```

### 2. When to Bump the Major Version

A new major version (`/v2/`) is required when a change is **backward-incompatible**:

- Removing or renaming a field in a response body
- Changing a required request parameter to optional (or vice versa) in a breaking way
- Changing the semantic meaning of an existing field
- Removing an endpoint
- Changing authentication requirements
- Altering error response structure

### 3. What Does NOT Require a New Version

The following changes are considered backward-compatible and can be made within `/v1/`:

- Adding new optional fields to request or response bodies
- Adding new endpoints
- Extending enumerations with new values
- Changing response header values (not structure)
- Performance improvements that don't change the contract

### 4. Deprecation Policy

| Phase         | Duration        | What Happens                                                         |
|---------------|-----------------|----------------------------------------------------------------------|
| **Announce**  | At version bump | Deprecation header `Sunset: Sat, 01 Jan 2027 00:00:00 GMT` added     |
| **Warning**   | 6 months min.   | `Warning: 299 - "v1 is deprecated, migrate to v2"` header on every response |
| **Sunset**    | After warning   | Endpoint returns `410 Gone`                                          |

### 5. Sunset Header

When an API version enters the deprecation period, all responses include:

```http
Sunset: Sat, 01 Jan 2027 00:00:00 GMT
Deprecation: true
```

Clients SHOULD monitor the `Sunset` and `Deprecation` headers and plan migrations accordingly.

## Gateway Compatibility

The API gateway supports the following version prefixes for routing:

- `/v1/*` — Current stable version
- `/health/*` — Health endpoints (unversioned; exempt from auth rate limits)
- Custom per-tenant prefix via `canonicalCustomerPrefix` configuration

See [`docs/api-contract-manifest.json`](../api-contract-manifest.json) for the full list of registered endpoints and their version prefixes.

## Client Guidance

### SDK Support

All official ApexMail SDKs accept the version as part of the base URL configuration:

```python
# Python SDK
client = ApexMail(
    api_key="am_live_...",
    base_url="https://api.apexmail.ee/v1",
)
```

```go
// Go SDK
client := apexmail.NewClient(
    apexmail.WithAPIKey("am_live_..."),
    apexmail.WithBaseURL("https://api.apexmail.ee/v1"),
)
```

### Migrating Between Versions

When a new API version is released:

1. Review the [changelog](./changelog.md) for breaking changes
2. Test against the new version in the staging environment
3. Update the base URL in your client configuration
4. Verify all integrations pass
5. Migrate before the sunset date

## Related Documents

- [API Contract Manifest](../api-contract-manifest.json) — Registered endpoints and route patterns
- [API Changelog](./changelog.md) — Historical record of API changes
- [API Authentication](./authentication.md) — Auth requirements per version
- [ADR-0005: SDK Generation and Versioning](../adr/0005-sdk-generation-and-versioning.md) — Architectural decision record
