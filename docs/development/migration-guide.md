# Migration and Upgrade Guide

> **ApexMail** — Production migration procedures, versioning policies, and upgrade checklists.

---

## Table of Contents

- [Database Migration System](#database-migration-system)
- [API Versioning](#api-versioning)
- [Plan and Pricing Changes](#plan-and-pricing-changes)
- [Breaking Change Policy](#breaking-change-policy)
- [SDK Updates](#sdk-updates)
- [Docker Image Updates](#docker-image-updates)
- [Configuration Changes](#configuration-changes)

---

## Database Migration System

### Migration Tooling

ApexMail uses a custom migration runner located at `tools/migrate/`. Migrations are co-located with the apps that own their schemas:

| App             | Migration Directory            |
|-----------------|--------------------------------|
| Billing         | `apps/billing/migrations/`     |
| DevEx (API)     | `apps/devex/migrations/`       |
| Edge Cases      | `apps/edge-cases/migrations/`  |
| Enterprise      | `apps/enterprise/migrations/`  |
| HA              | `apps/ha/migrations/`          |
| Isolation       | `apps/isolation/migrations/`   |
| Observability   | `apps/observability/migrations/`|
| Sales Autopilot | `apps/sales-autopilot/migrations/` |

### Migration File Naming

Migrations follow a **sequential numbering** scheme:

```
001_initial_schema.sql
002_add_pricing_tiers.sql
003_add_audit_columns.sql
```

Each migration file is numbered with a zero-padded prefix to guarantee deterministic ordering. The migration runner processes files in lexicographic order and records completed migrations in a `schema_migrations` tracking table to ensure idempotency.

### Forward-Only Policy

> **Production migrations are forward-only. There are no down migrations.**

Rollback in production is handled through **compensating migrations** — a new forward migration that reverses the effect of a previous one. This policy exists because:

1. **Data loss risk** — `DROP COLUMN` in a down migration permanently destroys data.
2. **Concurrent traffic** — Rolling back a schema while the application is serving requests introduces undefined behavior.
3. **Audit trail** — Every schema state is an append-only record of what happened and when.

### Running Migrations

```bash
# Run all pending migrations for a specific app
pnpm --filter @apexmail/billing migrate

# Run migrations via the shared tool
node tools/migrate/index.js --app billing

# Dry-run (prints SQL without executing)
node tools/migrate/index.js --app billing --dry-run
```

### Migration Best Practices

- **Always wrap DDL in transactions** where the database supports transactional DDL (PostgreSQL does).
- **Avoid long-running locks.** Use `CREATE INDEX CONCURRENTLY` for index additions on large tables.
- **Test migrations against a production-size dataset** before deploying.
- **Never modify a migration that has already been applied.** Create a new migration instead.
- **Include both the migration and application code** in the same release when schema and code are coupled.

---

## API Versioning

### Date-Based Versions

The DevEx app implements **date-based API versioning**. Clients specify the API version they were built against, and the server handles backward-compatible responses accordingly.

ApexMail maintains **5 API versions concurrently** at any given time. When a new version is introduced, the oldest version enters its deprecation window.

```
API-Version: 2025-06-01
API-Version: 2025-09-01
API-Version: 2025-12-01
API-Version: 2026-03-01
API-Version: 2026-06-01   ← current
```

### Deprecation Headers

When a client uses a deprecated API version, the response automatically includes deprecation headers:

```http
HTTP/1.1 200 OK
Deprecation: Sun, 01 Jun 2025 00:00:00 GMT
Sunset: Mon, 01 Dec 2025 00:00:00 GMT
Link: <https://docs.apexmail.io/api/changelog>; rel="deprecation"
```

| Header        | Purpose                                          |
|---------------|--------------------------------------------------|
| `Deprecation` | The date the version was marked deprecated       |
| `Sunset`      | The date the version will stop functioning       |
| `Link`        | URL to the changelog / migration guide           |

### Deprecation Timeline

All API versions receive a **minimum 6-month deprecation notice** before removal. The timeline is:

1. **Announcement** — Version marked deprecated in release notes and documentation.
2. **Headers active** — `Deprecation` and `Sunset` headers begin appearing in responses.
3. **Warning period** — Monthly email reminders to API key owners still using the deprecated version.
4. **Sunset** — Requests to the sunset version return `410 Gone` with a migration guide link.

---

## Plan and Pricing Changes

### Migration 002 — Price Update

Migration `002` in the billing app updated plan pricing across all tiers:

| Plan       | Previous Price | New Price  | Change   |
|------------|---------------|------------|----------|
| Pro        | $49/mo        | $59/mo     | +$10     |
| Growth     | $99/mo        | $129/mo    | +$30     |
| Scale      | $299/mo       | $399/mo    | +$100    |
| Enterprise | $999/mo       | $1,299/mo  | +$300    |

### Grandfathering Policy

Existing subscribers are **grandfathered at their current price** until their next renewal cycle:

- **Monthly subscribers** — Old price applies until the current billing period ends. The new price takes effect at the next renewal.
- **Annual subscribers** — Old price applies for the remainder of the annual term. The new price takes effect at annual renewal.
- **Enterprise contracts** — Custom pricing is honored for the full contract term regardless of list price changes.

Grandfathered pricing is tracked in the `subscriptions` table via the `price_locked_until` column. The billing worker checks this field before applying updated rates.

---

## Breaking Change Policy

ApexMail follows a strict backward-compatibility contract for its public API surface:

### What Is Stable (Will Not Change)

| Aspect                  | Guarantee                                                    |
|-------------------------|--------------------------------------------------------------|
| **Error envelope format** | The `{ error: { code, message, details } }` structure is permanent. |
| **HTTP status codes**     | Existing endpoints will not change their success/error status codes. |
| **Authentication flow**   | API key and OAuth2 authentication mechanisms are stable.      |
| **Webhook payload shape** | Existing fields in webhook payloads are never removed.        |

### Non-Breaking Changes (May Happen Without Notice)

These changes can occur in any release and are **not** considered breaking:

- **New fields added** to JSON response objects.
- **New optional query parameters** on existing endpoints.
- **New event types** in the webhook system.
- **New enum values** in status fields.
- **Performance improvements** that change response times.

> **Client implementation note:** Always ignore unknown JSON fields. Use permissive deserialization (e.g., `additionalProperties: true` in JSON Schema, `#[serde(deny_unknown_fields)]` should NOT be used).

### Breaking Changes (Require Deprecation Period)

The following changes require a full deprecation cycle (minimum 6 months):

- Removing or renaming an existing field.
- Changing the type of an existing field.
- Removing an endpoint.
- Changing the authentication requirements for an endpoint.
- Altering the semantics of an existing field (e.g., changing units).

---

## SDK Updates

### Versioning Policy

Both official SDKs follow **Semantic Versioning (semver)**:

| SDK                          | Package                     |
|------------------------------|-----------------------------|
| Node.js (`packages/sdk-node`) | `@apexmail/sdk-node`        |
| Python (`packages/sdk-python`)| `apexmail`                  |

```
MAJOR.MINOR.PATCH

MAJOR — Breaking changes to the SDK's public API surface
MINOR — New features, backward-compatible
PATCH — Bug fixes, backward-compatible
```

### Major Version Bumps

A major version bump occurs when:

- A public method signature changes.
- A required parameter is added to an existing method.
- Return types change in a backward-incompatible way.
- Minimum runtime version requirements increase (e.g., Node.js 18 → Node.js 20).

### Auto-Retry Behavior

All SDK versions maintain **consistent auto-retry behavior**:

- **Retryable status codes:** `408`, `429`, `500`, `502`, `503`, `504`
- **Retry strategy:** Exponential backoff with jitter
- **Default max retries:** 3
- **Respects `Retry-After` header** when present (both absolute date and delta-seconds formats)
- **Idempotency keys** are automatically generated for POST requests to prevent duplicate operations on retry

This behavior is consistent across SDK major versions. Upgrading the SDK will not change retry semantics unless explicitly documented in the changelog.

---

## Docker Image Updates

### Dockerfile Inventory

ApexMail ships three Dockerfiles, each responsible for a distinct runtime:

| Dockerfile             | Purpose                          | Default Port |
|------------------------|----------------------------------|-------------|
| `Dockerfile.api`       | REST API server (Express/Hono)   | 3000        |
| `Dockerfile.tracking`  | Pixel/click tracking service     | 3001        |
| `Dockerfile.worker`    | Background job processor         | —           |

### Build Architecture

All Dockerfiles use **multi-stage builds** with the following security and operational features:

```dockerfile
# Stage 1: Build
FROM node:20-alpine AS builder
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile && pnpm build

# Stage 2: Production
FROM node:20-alpine AS runner
RUN apk add --no-cache tini
RUN addgroup -g 1001 apexmail && adduser -u 1001 -G apexmail -s /bin/sh -D apexmail
USER apexmail
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/index.js"]
```

Key security measures:

| Feature         | Purpose                                                    |
|-----------------|------------------------------------------------------------|
| **tini**        | PID 1 init process — proper signal handling and zombie reaping |
| **Non-root user** | Container runs as `apexmail` (UID 1001), never as root    |
| **Alpine base** | Minimal attack surface, smaller image size                  |
| **Frozen lockfile** | Deterministic dependency resolution                     |

### Upgrade Procedure

```bash
# 1. Pull latest images
docker compose pull

# 2. Run database migrations BEFORE restarting services
docker compose run --rm api node tools/migrate/index.js --app billing
docker compose run --rm api node tools/migrate/index.js --app devex

# 3. Restart services with zero-downtime rolling update
docker compose up -d --remove-orphans

# 4. Verify health checks pass
curl -f http://localhost:3000/health/ready
curl -f http://localhost:3001/health/ready
```

### Health Check Endpoints

Each service exposes health check endpoints that must return `200 OK` before the service receives traffic:

| Endpoint          | Checks                                    |
|-------------------|-------------------------------------------|
| `/health/live`    | Process is running (liveness)             |
| `/health/ready`   | Database connected, migrations current, dependencies available (readiness) |

Docker Compose and orchestrators (Kubernetes, ECS) use the readiness endpoint to gate traffic. A service that fails readiness checks is removed from the load balancer pool until it recovers.

---

## Configuration Changes

### Environment Variable Validation

All environment variables are **validated at startup using Zod schemas**. If a required variable is missing or fails validation, the process exits immediately with a descriptive error message — it does not start serving traffic with invalid configuration.

```typescript
const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  API_KEY_SECRET: z.string().min(32),
  CORS_ORIGIN: z.string(),
  NODE_ENV: z.enum(['development', 'test', 'production']),
  // ...
});
```

### Production-Specific Requirements

When `NODE_ENV=production`, additional validation rules are enforced:

| Requirement                     | Validation Rule                                              |
|---------------------------------|--------------------------------------------------------------|
| **Secrets ≥ 32 characters**     | `JWT_SECRET`, `API_KEY_SECRET`, and all signing keys must be at least 32 characters. |
| **No wildcard CORS**            | `CORS_ORIGIN` must not be `*`. An explicit origin list is required. |
| **No dev-default secrets**      | Values like `change-me`, `secret`, `dev-secret`, `password` are rejected. |
| **TLS database connections**    | `DATABASE_URL` must include `sslmode=require` or equivalent. |

### Adding New Configuration

When a new release introduces a required environment variable:

1. **Release notes** document the new variable, its purpose, format, and example value.
2. **Zod schema** is updated with the new field and appropriate validators.
3. **Docker Compose files** (`docker-compose.yml`, `docker-compose.prod.yml`) are updated with the new variable.
4. **Startup validation** ensures the process fails fast if the variable is missing.

### Configuration Precedence

Environment variables are resolved in the following order (highest priority first):

1. Process environment (`ENV` set in shell or orchestrator)
2. `.env.production.local` (machine-specific overrides, git-ignored)
3. `.env.production` (production defaults)
4. `.env.local` (local overrides, git-ignored)
5. `.env` (shared defaults)

---

## Upgrade Checklist

Use this checklist for every ApexMail upgrade:

- [ ] Read the release notes for breaking changes and new required environment variables.
- [ ] Back up the database before running migrations.
- [ ] Run migrations in a staging environment first.
- [ ] Update environment variables as documented.
- [ ] Pull and build new Docker images.
- [ ] Run database migrations against production.
- [ ] Deploy new containers with rolling update strategy.
- [ ] Verify health check endpoints return `200 OK`.
- [ ] Monitor error rates and latency for 30 minutes post-deploy.
- [ ] Update SDK versions in client applications if applicable.
- [ ] Test webhook delivery with the new version.
- [ ] Confirm deprecated API version headers are correct.
