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

This crate has **no mailer** — it never sends email. When a data-subject
request is submitted (`POST /gdpr/submit`), the raw verification token is
written to the `dsr_verification_outbox` table **in the same transaction** as
the request (`gdpr_automation::submit_request`). The response reports
`token_delivered: false` because delivery has not happened yet at submission
time; it is a handoff:

1. `dsr_verification_outbox` row is created with status `pending`, the raw
   token, and the verify URL built from `GDPR_VERIFY_BASE_URL`.
2. The services that own mail delivery (**api-server / worker**) drain
   pending rows via `GdprAutomation::pending_verification_outbox(limit)`,
   send the token to the subject, and confirm with
   `GdprAutomation::mark_outbox(id)`.
3. Until step 2 is wired on the api-server side, delivery is a **manual ops
   step**: query pending rows and deliver the verify link. The token never
   appears in API responses or logs.
4. The retention sweep purges outbox rows once the request window
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
