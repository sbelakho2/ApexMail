+++
title = "Email Grader API"
description = "Score any sender domain or email submission across DNS health, SPF/DKIM/DMARC authentication, content quality, and reputation. Free for ApexMail customers."
template = "prose.html"
weight = 5
+++

The Email Grader scores deliverability across five deterministic dimensions:

- **DNS health** — MX redundancy, A records, SPF/DKIM/DMARC presence.
- **Authentication** — SPF strictness, DKIM key sizes, DMARC enforcement.
- **Spam likelihood** — Bayesian, header, content, and URL signals from the
  shared spam-filter engine.
- **Content quality** — Trigger phrases, ratio of links, HTML hygiene.
- **Reputation** — Lookups against the curated domain blocklist.

Every score is computed from observable signals; there is no opaque ML model
in the grading path.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/grader/check` | Public (rate-limited) | Domain-only check from DNS |
| POST | `/v1/grader/submit` | API key (`grader:write`) | Full email analysis, persisted |
| GET  | `/v1/grader/results/{id}` | API key (`grader:read`) | Fetch a stored result |
| GET  | `/v1/grader/history` | API key (`grader:read`) | List recent results, paginated |

## Domain check (public)

Rate-limited per source IP. The default limit is 10 requests per hour and is
configurable per-deployment.

```bash
curl -X POST https://api.apexmail.ee/v1/grader/check \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "selectors": ["default", "google", "selector1"]
  }'
```

Response (truncated):

```json
{
  "domain": "example.com",
  "score": 84,
  "grade": "A",
  "breakdown": {
    "dns_health": { "score": 90, "max": 100 },
    "authentication": { "score": 80, "max": 100 },
    "spam_likelihood": { "score": 90, "max": 100 },
    "reputation": { "score": 100, "max": 100 }
  },
  "findings": [
    { "severity": "info", "category": "dns", "message": "Only one MX record — add a backup MX for redundancy" }
  ],
  "recommendations": [
    "Email authentication is well configured — consider adding BIMI and MTA-STS for enhanced security"
  ]
}
```

## Submit email (authenticated)

Submit a complete email envelope for scoring. Results are persisted under your
tenant. Request size is capped (default: 256 KB combined body).

```bash
curl -X POST https://api.apexmail.ee/v1/grader/submit \
  -H "X-API-Key: $APEXMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "hello@example.com",
    "to": ["user@example.org"],
    "subject": "Welcome to ApexMail",
    "body_text": "Thanks for trying ApexMail!",
    "headers": { "List-Unsubscribe": "<mailto:unsub@example.com>" },
    "selectors": ["default"],
    "sender_ip": "203.0.113.10",
    "helo_hostname": "mail.example.com",
    "mail_from": "bounce@example.com"
  }'
```

When `sender_ip` and `helo_hostname` are supplied, the grader runs the same
SPF/DKIM/DMARC pipeline as the production MTA against the submitted message.
Without them, only DNS-readiness scoring is used and a finding is emitted to
make that explicit.

The response includes a `created_at` timestamp and a stable `id` you can use
to retrieve the result later.

## Retrieve a stored result

```bash
curl https://api.apexmail.ee/v1/grader/results/{id} \
  -H "X-API-Key: $APEXMAIL_API_KEY"
```

Returns 404 if the result does not belong to the calling tenant — results are
strictly scoped per-tenant at the database layer.

## List recent results

```bash
curl "https://api.apexmail.ee/v1/grader/history?page=1&per_page=20" \
  -H "X-API-Key: $APEXMAIL_API_KEY"
```

`per_page` is clamped to `[1, 100]`.

## Required scopes

| Endpoint | Scope |
|----------|-------|
| `POST /v1/grader/submit` | `grader:write` |
| `GET /v1/grader/results/{id}` | `grader:read` |
| `GET /v1/grader/history` | `grader:read` |

The wildcard scope `*` grants all of the above.

## Errors

All errors follow the standard ApexMail envelope:

```json
{ "error": { "code": "INVALID_INPUT", "message": "subject contains CR/LF" } }
```

| HTTP | Code | Meaning |
|------|------|---------|
| 400 | `INVALID_INPUT` | Missing or malformed fields |
| 400 | `INVALID_TENANT` | Auth context missing valid tenant UUID |
| 403 | `INSUFFICIENT_SCOPE` | API key missing the required scope |
| 404 | `NOT_FOUND` | Result not found in your tenant |
| 413 | `BODY_TOO_LARGE` | Combined body exceeds the configured cap |
| 429 | `RATE_LIMITED` | Public check rate limit exceeded |
| 500 | `PERSIST_FAILED` / `DB_ERROR` | Database write or read failure |
| 503 | `GRADER_DISABLED` | Grader is disabled in this deployment |

## Limits and configuration

| Setting | Default | Env var |
|---------|---------|---------|
| Public rate limit | 10 / hour / IP | `GRADER_RATE_LIMIT`, `GRADER_RATE_WINDOW` |
| Max body size | 256 KB | `GRADER_MAX_BODY_SIZE` |
| Domain cache TTL | 5 min | `GRADER_CACHE_TTL` |
| Default DKIM selectors | `default,google,dkim,selector1` | `GRADER_DKIM_SELECTORS` |
| Auth hostname | `grader.apexmail.ee` | `GRADER_AUTH_HOSTNAME` |
