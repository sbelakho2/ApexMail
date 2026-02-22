# API Changelog & Versioning Policy

This document describes ApexMail's API versioning policy, backward compatibility commitments, and a running log of API changes.

---

## Versioning Policy

### URL-Based Versioning

All API endpoints are prefixed with a version identifier:

```
https://api.apexmail.ee/v1/messages
https://api.apexmail.ee/v1/domains
https://api.apexmail.ee/v1/templates
```

The current stable version is **v1**.

### Date-Based API Versioning (Control Plane)

The DevEx subsystem supports date-based API versioning for fine-grained evolution without bumping the major version. Up to **5 date-based versions** are supported concurrently. When a version is scheduled for deprecation, responses include deprecation headers:

| Header                | Description                                               |
| --------------------- | --------------------------------------------------------- |
| `Deprecation`         | The date when this API version was deprecated (RFC 7234). |
| `Sunset`              | The date when this API version will stop working.         |
| `Link`                | URL to the migration guide for the successor version.     |

Example:
```
Deprecation: Mon, 01 Jun 2026 00:00:00 GMT
Sunset: Mon, 01 Dec 2026 00:00:00 GMT
Link: <https://docs.apexmail.dev/migration/2026-06>; rel="successor-version"
```

### SDK Versioning

ApexMail SDKs (Node.js, Python, Go, Ruby, PHP, Java) follow **Semantic Versioning (semver)**:

- **MAJOR** (`2.0.0`): Breaking changes to the SDK interface.
- **MINOR** (`1.1.0`): New features, backward-compatible.
- **PATCH** (`1.0.1`): Bug fixes, backward-compatible.

SDK versions are pinned to a specific API version. The SDK changelog documents which API version each SDK release targets.

---

## Backward Compatibility Commitment

We are committed to **not breaking existing integrations** within a major API version. The following guarantees apply to all `v1` endpoints:

### What We Will NOT Change (Non-Breaking Guarantees)

- **Existing endpoint URLs** will continue to work.
- **Existing request parameters** will not be removed or have their type changed.
- **Existing response fields** will not be removed or have their type changed.
- **Error codes** in the `error.code` field will not be removed or change meaning.
- **HTTP methods** for existing endpoints will not change.
- **Authentication mechanisms** (API key, Bearer token) will not be removed.

### What We MAY Change (Non-Breaking Additions)

The following changes are considered **non-breaking** and may happen at any time:

- Adding **new endpoints**.
- Adding **new optional request parameters** (with sensible defaults).
- Adding **new fields to response objects** (your code should ignore unknown fields).
- Adding **new values to enums** (e.g., a new event type or status).
- Adding **new HTTP headers** to responses.
- Adding **new webhook event types**.
- Changing **rate limits** (with advance notice).
- Improving **error messages** (the human-readable `message` field; `code` remains stable).

> **Important:** Your integration should be resilient to additive changes. Specifically:
> - Do not fail on unknown JSON fields in responses.
> - Do not fail on unknown enum values.
> - Do not fail on unknown webhook event types.

---

## Deprecation Policy

When an API feature needs to be removed or replaced:

1. **Minimum 6-month notice** — we will announce the deprecation at least 6 months before the feature is removed.
2. **Deprecation headers** — affected endpoints will return `Deprecation` and `Sunset` HTTP headers.
3. **Documentation** — the feature will be marked as deprecated in the API docs with a migration path.
4. **Email notification** — all account owners will receive an email notification about the deprecation.
5. **Dashboard banner** — a deprecation notice will appear in the ApexMail dashboard.
6. **Sunset** — after the sunset date, the deprecated feature will return `410 Gone` with a migration link in the response body.

### Deprecation Lifecycle

```
┌────────────┐    ┌────────────────────┐    ┌──────────────┐    ┌───────────┐
│  Current    │───▶│   Deprecated       │───▶│   Sunset     │───▶│  Removed  │
│  (active)   │    │   (6+ months)      │    │  (final day) │    │  (410)    │
└────────────┘    └────────────────────┘    └──────────────┘    └───────────┘
                   │                        │
                   │ Headers added          │ Feature stops
                   │ Docs updated           │ working
                   │ Email sent             │ Returns 410
```

---

## Breaking vs. Non-Breaking Changes

| Category              | Breaking ❌                                   | Non-Breaking ✅                                 |
| --------------------- | --------------------------------------------- | ----------------------------------------------- |
| Endpoints             | Removing or renaming an endpoint              | Adding a new endpoint                           |
| Request parameters    | Removing or renaming a required parameter     | Adding a new optional parameter                 |
| Response fields       | Removing or changing the type of a field      | Adding a new field                              |
| Enum values           | Removing an enum value                        | Adding a new enum value                         |
| Error codes           | Removing or changing the meaning of a code    | Adding a new error code                         |
| HTTP status codes     | Changing success status (e.g., 200 → 201)     | Adding a new error status for new scenarios     |
| Authentication        | Removing an auth method                       | Adding a new auth method                        |
| Rate limits           | Lowering limits without notice                | Raising limits, or lowering with advance notice |
| Webhooks              | Removing an event type                        | Adding a new event type                         |

Breaking changes will only occur in a new major version (e.g., `/v2`) and will come with a migration guide.

---

## Error Format Stability Guarantee

All API errors follow a stable envelope format that will not change within v1:

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "You have exceeded the rate limit of 1000 requests per minute.",
    "details": {
      "limit": 1000,
      "remaining": 0,
      "resetAt": "2026-02-09T12:01:00Z"
    }
  },
  "requestId": "req_abc123def456"
}
```

| Field              | Type   | Guaranteed | Description                                     |
| ------------------ | ------ | :--------: | ----------------------------------------------- |
| `error`            | object | ✅         | Always present on error responses.              |
| `error.code`       | string | ✅         | Machine-readable error code. Stable and unique. |
| `error.message`    | string | ✅         | Human-readable description. May change wording. |
| `error.details`    | object | ✅         | Additional context. Fields may be added.        |
| `requestId`        | string | ✅         | Unique request identifier for support/debugging.|

**Stability rules:**
- `error.code` values will not be removed or change meaning.
- `error.message` wording may change (do not parse it programmatically).
- New fields may be added to `error.details` (non-breaking).
- `requestId` will always be present and always be a string.

---

## How to Subscribe to API Updates

Stay informed about API changes through these channels:

| Channel                 | Description                                          |
| ----------------------- | ---------------------------------------------------- |
| **Changelog RSS feed**  | `https://docs.apexmail.dev/api/changelog.rss`        |
| **Email notifications** | Account owners receive deprecation and major change notices automatically. Opt in under **Settings → Notifications**. |
| **Dashboard banner**    | Deprecation warnings appear in the ApexMail dashboard. |
| **API response headers**| `Deprecation` and `Sunset` headers on affected endpoints. |
| **Status page**         | `https://status.apexmail.dev` — subscribe for incident and maintenance updates. |
| **GitHub releases**     | SDK releases are published on GitHub with changelogs. |

---

## Migration Guides

When a breaking change is introduced in a new version, a migration guide will be published. Migration guides include:

1. **Summary of changes** — what changed and why.
2. **Side-by-side comparison** — old vs. new request/response formats.
3. **Code examples** — updated SDK usage in Node.js and Python.
4. **Timeline** — deprecation date, sunset date, and removal date.
5. **Testing guidance** — how to test against the new version using the sandbox environment.

Migration guides will be linked from:
- The `Link` header on deprecated endpoints.
- The API documentation.
- The deprecation email notification.

---

## Changelog

### v1 — Initial Stable Release

**Released:** 2025

The inaugural stable release of the ApexMail API. All endpoints are production-ready and covered by the backward compatibility commitment above.

#### Messages API

| Endpoint                        | Method | Description                             |
| ------------------------------- | ------ | --------------------------------------- |
| `/v1/messages`                  | POST   | Send a single email message.            |
| `/v1/messages/batch`            | POST   | Send up to 1,000 messages in one call.  |
| `/v1/messages/:id`              | GET    | Retrieve a message by ID.               |
| `/v1/messages`                  | GET    | List messages with filtering and pagination. |
| `/v1/messages/:id/cancel`       | POST   | Cancel a scheduled or queued message.   |

#### Domains API

| Endpoint                        | Method | Description                             |
| ------------------------------- | ------ | --------------------------------------- |
| `/v1/domains`                   | POST   | Register a new sending domain.          |
| `/v1/domains`                   | GET    | List all domains.                       |
| `/v1/domains/:id`               | GET    | Get domain details and verification status. |
| `/v1/domains/:id/verify`        | POST   | Trigger DNS verification.               |
| `/v1/domains/:id/dns-records`   | GET    | Get required DNS records.               |
| `/v1/domains/:id/auth-score`    | GET    | Get authentication score (SPF, DKIM, DMARC). |
| `/v1/domains/:id/health`        | GET    | Get domain health metrics.              |
| `/v1/domains/:id/mta-sts`       | GET    | Get MTA-STS policy status.              |
| `/v1/domains/:id/bimi`          | GET    | Get BIMI configuration status.          |

#### Templates API

| Endpoint                        | Method | Description                             |
| ------------------------------- | ------ | --------------------------------------- |
| `/v1/templates`                 | POST   | Create a new template.                  |
| `/v1/templates`                 | GET    | List all templates.                     |
| `/v1/templates/:id`             | GET    | Get a template by ID.                   |
| `/v1/templates/:id`             | PUT    | Update a template (creates a new version). |
| `/v1/templates/:id`             | DELETE | Delete a template.                      |
| `/v1/templates/:id/versions`    | GET    | List all versions of a template.        |
| `/v1/templates/:id/render`      | POST   | Render a template with test data.       |
| `/v1/templates/:id/preview`     | GET    | Get a visual preview of a template.     |

#### Webhooks API

| Endpoint                        | Method | Description                             |
| ------------------------------- | ------ | --------------------------------------- |
| `/v1/webhooks`                  | POST   | Create a new webhook.                   |
| `/v1/webhooks`                  | GET    | List all webhooks.                      |
| `/v1/webhooks/:id`              | GET    | Get a webhook by ID.                    |
| `/v1/webhooks/:id`              | PUT    | Update a webhook.                       |
| `/v1/webhooks/:id`              | DELETE | Delete a webhook.                       |
| `/v1/webhooks/:id/test`         | POST   | Send a test event to the webhook.       |
| `/v1/webhooks/:id/enable`       | POST   | Enable a disabled webhook.              |
| `/v1/webhooks/:id/disable`      | POST   | Disable a webhook.                      |
| `/v1/webhooks/:id/deliveries`   | GET    | List delivery logs for a webhook.       |

#### Events API

| Endpoint                        | Method | Description                             |
| ------------------------------- | ------ | --------------------------------------- |
| `/v1/events`                    | GET    | List events with filtering.             |
| `/v1/events/stream`             | GET    | Stream events via Server-Sent Events.   |
| `/v1/events/stats`              | GET    | Get aggregate event statistics.         |
| `/v1/events/timeline`           | GET    | Get event timeline for a message or contact. |
| `/v1/events/bounces`            | GET    | List bounce events.                     |
| `/v1/events/complaints`         | GET    | List complaint events.                  |

#### Analytics API

| Endpoint                        | Method | Description                             |
| ------------------------------- | ------ | --------------------------------------- |
| `/v1/analytics/overview`        | GET    | Get high-level analytics summary.       |
| `/v1/analytics/timeseries`      | GET    | Get time-series data for sends, opens, clicks, etc. |
| `/v1/analytics/campaigns`       | GET    | Get per-campaign analytics.             |
| `/v1/analytics/domains`         | GET    | Get per-domain analytics and health.    |
| `/v1/analytics/export`          | POST   | Export analytics data as CSV.           |

#### Suppressions API

| Endpoint                        | Method | Description                             |
| ------------------------------- | ------ | --------------------------------------- |
| `/v1/suppressions`              | POST   | Add an address to the suppression list. |
| `/v1/suppressions`              | GET    | List suppressed addresses.              |
| `/v1/suppressions/:id`          | GET    | Get a suppression entry.                |
| `/v1/suppressions/:id`          | DELETE | Remove an address from the suppression list. |
| `/v1/suppressions/bulk`         | POST   | Bulk add suppressions (up to 10,000).   |
| `/v1/suppressions/import`       | POST   | Import suppressions from CSV (up to 100,000). |
| `/v1/suppressions/export`       | GET    | Export the full suppression list.        |
| `/v1/suppressions/check`        | GET    | Check if an address is suppressed.      |

#### Auth API

| Endpoint                        | Method | Description                             |
| ------------------------------- | ------ | --------------------------------------- |
| `/v1/auth/login`                | POST   | Authenticate and receive tokens.        |
| `/v1/auth/me`                   | GET    | Get the current authenticated user.     |
| `/v1/auth/api-keys`             | POST   | Create a new API key.                   |
| `/v1/auth/api-keys`             | GET    | List all API keys.                      |
| `/v1/auth/api-keys/:id`         | DELETE | Revoke an API key.                      |
| `/v1/auth/csrf`                 | GET    | Get a CSRF token for browser sessions.  |
| `/v1/auth/logout`               | POST   | Logout and revoke the current token.    |
| `/v1/auth/refresh`              | POST   | Refresh an expired access token.        |

---

## Previous Versions

No previous API versions exist. v1 is the initial release.

---

## v1 Updates

### 2025 — React Email Support + Multi-Language SDKs

#### New: React Email template engine

Templates now support `engine: "react"` — compose emails as JSX components using `@react-email/components`. Templates are transpiled and rendered server-side in a secure VM sandbox.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/templates/react-email/starter` | GET | Get a JSX starter template |
| `/v1/templates/react-email/validate` | POST | Validate a JSX source string |

New error codes: `INVALID_REACT_EMAIL_SOURCE`, `REACT_EMAIL_TRANSPILE_ERROR`, `REACT_EMAIL_NO_DEFAULT_EXPORT`, `REACT_EMAIL_EXECUTION_ERROR`, `REACT_EMAIL_RENDER_ERROR`.

#### New: Official SDKs for Go, Ruby, PHP, Java

| Language | Package |
|----------|---------|
| Go | `github.com/Bel-Consulting-OU/ApexMail/packages/sdk-go` |
| Ruby | `apexmail` (RubyGems) |
| PHP | `apexmail/apexmail-php` (Packagist) |
| Java | `ee.apexmail:apexmail-java` (Maven Central) |

All SDKs cover: `emails` (send, batch, get, list), `domains` (create, list, get, verify, delete, health), `webhooks` (create, list, get, update, delete), `templates` (create, list, get, update, delete, render, React Email helpers), `suppressions` (add, list, check, delete), and `events` (list, get, getByMessage).

---

---

## Further Reading

- [Troubleshooting Guide](../user-guide/troubleshooting.md) — solutions for common API errors
- [Glossary](../user-guide/glossary.md) — definitions of terms used in this document
- [Contact Management](../user-guide/contacts.md) — user guide for contact and list management
