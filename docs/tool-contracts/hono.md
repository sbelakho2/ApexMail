# Tool Contract: Hono Framework

> Internal engineering document — specifies the interface contract for how ApexMail uses the Hono HTTP framework.

| Field | Value |
|-------|-------|
| **Framework** | Hono v4+ |
| **Runtime** | Node.js 22 LTS |
| **Language** | TypeScript (strict mode) |
| **Role** | HTTP API framework for all REST endpoints |
| **Entry Point** | `apps/api/src/index.ts` |

---

## 1. Middleware Chain

Middleware executes in **strict order**. The order below is mandatory and MUST NOT be rearranged without team review.

```
Request
  │
  ├─ 1. Request ID          — Assign unique X-Request-Id header
  ├─ 2. Request Logger       — Log method, path, start time
  ├─ 3. CORS                 — Cross-origin rules
  ├─ 4. Security Headers     — X-Content-Type-Options, etc.
  ├─ 5. Auth                 — Validate Bearer token / API key
  ├─ 6. Rate Limit           — Per-tenant / per-IP rate check (Redis)
  ├─ 7. Tenant Context       — Load tenant, set app.current_tenant_id
  ├─ 8. Request Validation   — Validate body/query/params (Zod)
  ├─ 9. Route Handler        — Business logic
  ├─ 10. Response Logger     — Log status, duration
  │
Response
```

### Middleware Rules

1. **Auth** middleware sets `c.set('user', user)` and `c.set('tenantId', tenantId)` on the Hono context.
2. **Tenant Context** middleware calls `SET LOCAL app.current_tenant_id` on the database connection for RLS enforcement.
3. **Rate Limit** middleware returns `429 Too Many Requests` with `Retry-After` header when exceeded.
4. Middleware that needs to skip certain routes (e.g., auth skip for public endpoints) uses a route allowlist, not conditional logic inside the middleware.
5. Every middleware calls `await next()` exactly once — never zero times (swallows request) and never twice (double execution).

---

## 2. Route Registration

### File Structure

```
apps/api/src/
├── index.ts              # App entry, middleware registration
├── routes/
│   ├── auth.ts           # POST /auth/login, /auth/register, etc.
│   ├── campaigns.ts      # CRUD /campaigns
│   ├── contacts.ts       # CRUD /contacts
│   ├── emails.ts         # POST /emails/send, GET /emails/:id
│   ├── templates.ts      # CRUD /templates
│   ├── webhooks.ts       # POST /webhooks/stripe, /webhooks/ses
│   ├── health.ts         # GET /health, /ready
│   └── tenants.ts        # Tenant management
└── middleware/
    ├── auth.ts
    ├── cors.ts
    ├── rate-limit.ts
    ├── tenant-context.ts
    ├── validation.ts
    └── request-id.ts
```

### Registration Pattern

```ts
// routes/campaigns.ts
import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { createCampaignSchema, updateCampaignSchema } from '../schemas/campaigns';

const campaigns = new Hono();

campaigns.get('/', listCampaigns);
campaigns.post('/', zValidator('json', createCampaignSchema), createCampaign);
campaigns.get('/:id', getCampaign);
campaigns.put('/:id', zValidator('json', updateCampaignSchema), updateCampaign);
campaigns.delete('/:id', deleteCampaign);

export { campaigns };
```

```ts
// index.ts
app.route('/api/v1/campaigns', campaigns);
app.route('/api/v1/contacts', contacts);
// ...
```

### Rules

1. All API routes are prefixed with `/api/v1/`.
2. Route files export a `Hono` instance — they do NOT export raw handler functions.
3. Route parameter naming: `:id` for primary resource, `:contactId` for nested resources.
4. No business logic in route files — handlers call service-layer functions.
5. Webhook routes (`/webhooks/*`) skip auth middleware but validate provider-specific signatures.

---

## 3. Error Handling

### AppError Class

All application errors extend `AppError`:

```ts
class AppError extends Error {
  constructor(
    public statusCode: number,
    public code: string,
    message: string,
    public details?: Record<string, unknown>,
  ) {
    super(message);
  }
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
| 429 | `RATE_LIMITED` | Rate limit exceeded |
| 500 | `INTERNAL_ERROR` | Unhandled server error |

### Global Error Handler

```ts
app.onError((err, c) => {
  if (err instanceof AppError) {
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

1. Handlers MUST throw `AppError` for known error conditions — never return raw status codes.
2. Unexpected errors (thrown by libraries, DB, etc.) are caught by the global handler and logged with full stack trace.
3. Error responses NEVER leak internal details (stack traces, SQL errors, file paths) to the client.

---

## 4. Request Validation

All request inputs are validated using **Zod** schemas via `@hono/zod-validator`.

### Validation Targets

| Target | Validator | Example |
|--------|-----------|---------|
| JSON body | `zValidator('json', schema)` | POST/PUT payloads |
| Query params | `zValidator('query', schema)` | `?page=1&limit=20` |
| URL params | `zValidator('param', schema)` | `/:id` (UUID format) |
| Headers | `zValidator('header', schema)` | Custom headers (rare) |

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
- The spec is served at `/api/v1/openapi.json`.
- A Scalar UI is served at `/api/v1/docs` for interactive documentation.
- CI validates that the OpenAPI spec is up to date and matches route definitions.
- The SDK packages (`packages/sdk-node`, `packages/sdk-python`) are generated from the OpenAPI spec.

---

*Last updated: 2026-02-09*
