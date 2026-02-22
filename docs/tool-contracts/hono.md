# Tool Contract: Hono Framework

> Internal engineering document — specifies the interface contract for how ApexMail uses the Hono HTTP framework.

| Field | Value |
|-------|-------|
| **Framework** | Hono v4+ |
| **Runtime** | Node.js ≥ 20.11.0 |
| **Language** | TypeScript (strict mode) |
| **Role** | HTTP API framework for all REST endpoints |
| **Entry Point** | `apps/api/src/index.ts` |

---

## 1. Middleware Chain

Middleware executes in **strict order**. The order below is mandatory and MUST NOT be rearranged without team review.

```
Request
  │
  ├─ 1.  Request ID          — Assigns unique X-Request-ID
  ├─ 2.  Server Timing       — Adds Server-Timing header
  ├─ 3.  Compress            — gzip/br response compression
  ├─ 4.  ETag                — Response caching support
  ├─ 5.  Security Headers    — CSP, HSTS, X-Frame-Options, etc.
  ├─ 6.  Timeout             — 30 s limit → 504 REQUEST_TIMEOUT
  ├─ 7.  Body Limit          — 10 MB default, 25 MB for upload routes
  ├─ 8.  Pretty JSON         — Human-readable JSON in development
  ├─ 9.  Null-byte Sanitizer — Rejects payloads containing null bytes
  ├─ 10. Extra Security Hdrs — X-API-Version, additional HSTS config
  ├─ 11. CORS                — Cross-origin rules
  ├─ 12. Trusted Proxy       — Validates X-Forwarded-For sources
  ├─ 13. Request Logger      — Logs method, path, start time
  ├─ [public routes: /v1/auth/login, /v1/auth/forgot-password]
  │    ├─ Rate Limit         — Brute-force protection for public auth
  │
  ├─ [authenticated API routes: /v1/*]
  │    ├─ Auth               — Validates X-API-Key or Bearer JWT
  │    ├─ CSRF Protection    — State-changing requests
  │    ├─ Rate Limit         — Per-tenant + per-IP (Redis)
  │    ├─ Idempotency        — /messages/*, /domains/*, /templates/*,
  │    │                        /suppressions/*, /dedicated-ips/*
  │    └─ Route Handler      — Business logic
  │
Response
```

### Middleware Rules

1. **Auth** middleware sets `c.set('tenantId', ...)`, `c.set('userId', ...)`, `c.set('apiKeyId', ...)`, and `c.set('scopes', [...])` on the Hono context.
2. **Rate Limit** middleware returns `429 Too Many Requests` with `Retry-After` header when exceeded; error code is `RATE_LIMIT_EXCEEDED`.
3. Public endpoints (`/v1/auth/login`, `/v1/auth/forgot-password`) are mounted on a separate sub-app without the auth middleware — not via an allowlist inside auth middleware.
4. CSRF protection runs after auth so the user context (`userId`) is available.
5. Every middleware calls `await next()` exactly once — never zero times (swallows request) and never twice (double execution).

---

## 2. Route Registration

### File Structure

```
apps/api/src/
├── index.ts                # App entry, middleware registration
├── app.ts                  # Hono app factory
├── routes/
│   ├── auth.ts             # POST /auth/login, GET /auth/me, /auth/api-keys
│   ├── campaigns.ts        # CRUD /campaigns
│   ├── contacts.ts         # CRUD /contacts
│   ├── messages.ts         # POST /messages, /messages/batch
│   ├── domains.ts          # CRUD /domains, /domains/:id/verify
│   ├── templates.ts        # CRUD /templates
│   ├── suppressions.ts     # CRUD /suppressions
│   ├── events.ts           # GET /events
│   ├── webhooks.ts         # CRUD /webhooks
│   ├── analytics.ts        # GET /analytics/*
│   ├── ai-insights.ts      # GET /analytics/ai/*
│   ├── dedicated-ips.ts    # CRUD /dedicated-ips
│   ├── automations.ts      # CRUD /automations
│   ├── scim.ts             # SCIM 2.0 /scim/*
│   ├── support.ts          # GET /support
│   └── health.ts           # GET /health
└── middleware/
    ├── auth.ts             # API key + JWT authentication
    ├── rate-limiter.ts     # Per-tenant + per-IP rate limiting
    ├── idempotency.ts      # X-Idempotency-Key support
    ├── csrf.ts             # CSRF token protection
    ├── error-handler.ts    # ApiError class + global onError
    └── request-id.ts      # X-Request-ID injection
```

### Registration Pattern

```ts
// routes/campaigns.ts
import { Hono } from 'hono';
import { z } from 'zod';
import type { AppEnv, AppContext } from '../app.js';

const createCampaignSchema = z.object({ /* ... */ });

export function campaignsRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();

  router.get('/', async (c) => { /* list */ });
  router.post('/', async (c) => {
    const body = await c.req.json();
    const input = createCampaignSchema.parse(body); // Inline Zod validation
    /* ... */
  });
  router.get('/:id', async (c) => { /* get */ });
  router.delete('/:id', async (c) => { /* delete */ });

  return router;
}
```

```ts
// index.ts
app.route('/v1/campaigns', campaigns);
app.route('/v1/contacts', contacts);
// ...
```

### Rules

1. All API routes are prefixed with `/v1/`.
2. Route files export a `Hono` instance — they do NOT export raw handler functions.
3. Route parameter naming: `:id` for primary resource, `:contactId` for nested resources.
4. No business logic in route files — handlers call service-layer functions.
5. Webhook routes (`/webhooks/*`) skip auth middleware but validate provider-specific signatures.

---

## 3. Error Handling

### ApiError Class

All application errors are created via the `ApiError` factory class:

```ts
class ApiError extends Error {
  constructor(
    public statusCode: number,
    public code: string,
    message: string,
    public details?: Record<string, unknown>,
  ) {
    super(message);
  }

  // Factory methods
  static badRequest(message: string, code?: string, details?: Record<string, unknown>): ApiError
  static unauthorized(message: string, code?: string): ApiError
  static forbidden(message: string, code?: string): ApiError
  static notFound(resource: string): ApiError
  static conflict(message: string, code?: string): ApiError
  static tooManyRequests(message: string, code?: string): ApiError
  static internal(message: string): ApiError
}
```

### Standard Error Codes

| Status | Code | Usage |
|--------|------|-------|
| 400 | `VALIDATION_ERROR` | Request body/query failed Zod validation |
| 401 | `UNAUTHORIZED` | Missing or invalid auth token |
| 403 | `FORBIDDEN` | Authenticated but insufficient permissions |
| 404 | `NOT_FOUND` | Resource does not exist (or not visible to tenant) |
| 409 | `CONFLICT` | Duplicate resource (e.g., email already exists) |
| 422 | `UNPROCESSABLE` | Valid syntax but semantically invalid (e.g., send to bounced contact) |
| 429 | `RATE_LIMIT_EXCEEDED` | Rate limit exceeded |
| 500 | `INTERNAL_ERROR` | Unhandled server error |

### Global Error Handler

```ts
app.onError((err, c) => {
  if (err instanceof ApiError) {
    return c.json({
      success: false,
      error: {
        code: err.code,
        message: err.message,
        details: err.details,
      },
    }, err.statusCode);
  }

  // Unexpected error — log full stack, return generic message
  logger.error('Unhandled error', { err, requestId: c.get('requestId') });
  return c.json({
    success: false,
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred',
    },
  }, 500);
});
```

### Rules

1. Handlers MUST throw `ApiError` for known error conditions — never return raw status codes.
2. Unexpected errors (thrown by libraries, DB, etc.) are caught by the global handler and logged with full stack trace.
3. Error responses NEVER leak internal details (stack traces, SQL errors, file paths) to the client.

---

## 4. Request Validation

All request inputs are validated using **Zod** schemas invoked inline in route handlers.

### Validation Targets

| Target | Method | Example |
|--------|--------|---------|
| JSON body | `schema.parse(await c.req.json())` | POST/PUT payloads |
| Query params | `schema.parse(c.req.query())` | `?page=1&limit=20` |
| URL params | UUID regex validated before DB queries | `/:id` (UUID format) |
| Headers | `c.req.header('X-...')` with manual checks | Custom headers |

### Schema Location

- Schemas live in `apps/api/src/schemas/<resource>.ts`.
- Schemas are co-located with their route module.
- Shared schemas (pagination, UUID params) are in `apps/api/src/schemas/common.ts`.

### Rules

1. Every POST/PUT/PATCH endpoint MUST have a Zod body schema.
2. Schemas enforce type, format, min/max length, and business constraints.
3. Validation errors return 400 with field-level error details.
4. Schemas strip unknown keys (`.strict()` or Zod defaults) — no extra fields pass through.

---

## 5. Response Format

All API responses use a consistent **JSON envelope**:

### Success Response

```json
{
  "success": true,
  "data": { ... },
  "meta": {
    "page": 1,
    "limit": 20,
    "total": 142
  }
}
```

### Error Response

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request body",
    "details": {
      "email": "Invalid email format"
    }
  }
}
```

### Rules

1. Every response has `success: boolean` at the top level.
2. Successful responses put data in the `data` field. Lists include `meta` with pagination.
3. Error responses put error info in the `error` field with `code` and `message`.
4. Dates are ISO 8601 strings (`2026-02-09T12:00:00.000Z`).
5. IDs are UUIDs as strings.
6. Null fields are included in the response (not omitted) for consistent shape.
7. HTTP status codes match the response: 200 (OK), 201 (created), 204 (no content / delete), 4xx/5xx (errors).

---

## 6. OpenAPI Generation

- OpenAPI 3.1 specification is auto-generated from Zod schemas using `@hono/zod-openapi`.
- The spec is served at `/v1/openapi.json`.
- A Scalar UI is served at `/v1/docs` for interactive documentation.
- CI validates that the OpenAPI spec is up to date and matches route definitions.
- The SDK packages (`packages/sdk-node`, `packages/sdk-python`) are generated from the OpenAPI spec.

---

*Last updated: 2026-02-09*
