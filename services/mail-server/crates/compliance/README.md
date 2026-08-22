# compliance

Compliance enforcement — GDPR, HIPAA, SOC 2, content scanning.

## Overview

The `compliance` crate enforces regulatory and policy compliance across ApexMail. It implements GDPR data-subject rights, HIPAA safeguards, SOC 2 audit controls, automated content scanning, and DSAR rate limiting to ensure that email processing and storage meet industry and legal requirements.

## DSAR Rate Limiting

The crate includes a dedicated DSAR (Data Subject Access Request) rate limiter at [`src/dsar_rate_limit.rs`](src/dsar_rate_limit.rs) implementing the following limits:

| Limit Type | Value | Scope |
|-----------|-------|-------|
| Per-user submission | 1/24h | Email address |
| Per-tenant submission | 100/24h | Tenant ID |
| Per-IP submission | 5/1h | IP address |
| Verification attempts | 5/token/1h | Token hash |

The rate limiter supports dual-mode operation: Redis-backed (primary) with in-memory `moka` cache fallback.

## How DSR verification tokens reach data subjects (ops)

When a data-subject request is submitted (`POST /gdpr/submit`), the raw
verification token is written to the `dsr_verification_outbox` table **in
the same transaction** as the request (`gdpr_automation::submit_request`).
The response reports `token_delivered: false` because delivery is queued
asynchronously — the full flow is:

1. `dsr_verification_outbox` row is created with status `pending`, the raw
   token, and the verify URL built from `GDPR_VERIFY_BASE_URL`.
2. The **outbox flush job** ([`src/dsr_outbox_flush.rs`](src/dsr_outbox_flush.rs),
   cron job 7 in `src/bin/server.rs`, every 60s) drains the oldest pending
   rows and queues each one as real mail through the platform's system-email
   path: a `messages` audit row plus an `email_queue` row (both column
   families, priority 5, tags `dsr-verification`) under the verified system
   sender domain (`system_internal_tenant01` / `apexmail.ee`, resolved with
   the same readiness predicate api-server's system sender uses). The
   delivery worker then sends it like any other queued mail.
3. The queue insert and the `status='sent'` outbox update commit in **one
   transaction per row** (at-most-once queuing; concurrent flushers cannot
   double-send). Failures increment `attempts` and retry on the next tick
   until `COMPLIANCE_DSR_FLUSH_MAX_ATTEMPTS` (default 5), after which the
   row parks as `failed`. If the system sender domain is not DKIM/SES-ready
   the tick skips **without** burning attempts. The batch per tick is
   bounded by `COMPLIANCE_DSR_FLUSH_BATCH` (default 25).
4. The email body carries the verify URL and the raw token (the subject
   needs both). Envelope sender: `COMPLIANCE_SYSTEM_FROM`
   (default `noreply@apexmail.ee` — must live on the system domain or the
   worker rejects the row). The token never appears in API responses or
   logs.
5. The retention sweep purges outbox rows once the request window
   (`GDPR_REQUEST_EXPIRATION_DAYS`, default 30) has passed — stale raw
   tokens do not linger.

## Retention enforcement (audit H-6)

The RET-001..023 registry ([`src/retention.rs`](src/retention.rs)) is
enforced by a daily sweep ([`src/retention_sweep.rs`](src/retention_sweep.rs),
wired as cron job 6 in `src/bin/server.rs`):

- Purges expired `message_events` / `tracking_events` / `engagement_events`
  per the registry's default-tier durations (RET-007/009/010 = 30 days),
  skipping tenants with `tenants.legal_hold = true` and counting the skips.
- Purges expired `gdpr_exports` (7-day window, same as
  `GdprAutomation::enforce_retention`).
- Trims `audit_logs` per `AUDIT_RETENTION_DAYS` via `AuditLogger::archive()`
  (rows only leave the live table when verifiably archived).
- Purges stale `dsr_verification_outbox` rows past the request window.
- Writes one `retention_report` row per run (per-category
  considered/deleted/skipped-by-legal-hold counts), so the policy is
  observable: `SELECT report FROM retention_report ORDER BY ran_at DESC LIMIT 1;`

Stores this crate cannot reach are listed in every report as **out of scope**
with their registry durations — ClickHouse analytics (RET-007/009/010),
backups (RET-021, enforced by the `ha` crate's `BACKUP_RETENTION_DAYS`
cleanup, default 90 days), and mailstore blobs (RET-001/006/023).

## Breach notification workflow

[`src/breach_notification.rs`](src/breach_notification.rs) implements the
internal breach-report lifecycle
(`active → notified_dpa → notified_subjects → resolved`), tracking the GDPR
72-hour and HIPAA 60-day deadlines from discovery, issuing HMAC-signed
notification documents, and audit-logging every transition. Exposed on the
service router (bearer-authenticated, internal):

- `POST /breaches` — record a breach (starts the deadline clocks)
- `GET /breaches/{tenant_id}` — list reports
- `POST /breaches/{id}/notify-dpa` — record supervisory-authority notification
- `POST /breaches/{id}/notify-subjects` — record subject notification
- `POST /breaches/{id}/resolve` — close the report

Email dispatch is NOT automated: `BREACH_NOTIFICATION_EMAILS` recipients are
logged for the on-call operator at report time. Customer notification timing
is governed by the DPA ("without undue delay"), not by this service.

## Usage

This crate is an internal workspace member of the ApexMail mail-server. Add it as a dependency:

```toml
compliance = { path = "../compliance" }
```

## Development

```sh
cargo test -p compliance
cargo clippy -p compliance
```

DB-backed tests (`tests/gdpr_compliance_db_tests.rs`) need
`TEST_DATABASE_URL` (and `TEST_REDIS_URL` for the queue/erasure tests);
without them the tests skip.
