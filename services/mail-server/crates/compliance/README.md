# compliance

Compliance enforcement — GDPR, HIPAA, SOC 2, content scanning.

## Overview

The `compliance` crate enforces regulatory and policy compliance across ApexMail. It implements GDPR data-subject rights, HIPAA safeguards, SOC 2 audit controls, automated content scanning, and DSAR rate limiting to ensure that email processing and storage meet industry and legal requirements.

## Schema ownership — no runtime DDL

The compliance service owns **no runtime schema DDL**. Every table it uses is
created by numbered migrations in `services/mail-server/migrations` (the DSR
verification outbox, breach state machine and retention report moved there in
migration 213; the GDPR governance registry in migration 214), applied by the
`migrator` deploy gate before the service starts. Production compliance
credentials can therefore be **DML-only** (SELECT/INSERT/UPDATE/DELETE).

Startup writes are limited to idempotent DML seeds: the SOC2 control catalog
and the GDPR governance registry / retention classes
(`compliance::bootstrap::build_state`).

Release tests:
`crates/compliance/tests/gdpr_governance_release_tests.rs` includes a source
scan forbidding DDL in `src/`, and
`compliance_boots_and_processes_with_dml_only_role` boots the complete service
against a role with no CREATE/ALTER/DROP privilege and proves it processes a
DSR, a breach through the receipt gate, and a retention sweep.

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

- Purges expired rows from the canonical `events` (RET-007/009/010 = 30 days)
  and `messages` (RET-001/002 = 7 days) stores, skipping tenants with
  `tenants.legal_hold = true` and counting the skips.
- Advances the legally-restricted archive through statutory expiry →
  deletion (source records are removed only after the statutory expiry).
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
breach lifecycle as an explicit, evidence-bearing state machine:

```
detected → triage → notifiable | not_notifiable
notifiable → authority_queued → authority_submitted → authority_acknowledged
```

- `POST /breaches` — record a breach (starts the 72h GDPR / 60-day HIPAA clocks)
- `GET /breaches/{tenant_id}` — list reports
- `POST /breaches/{id}/triage` — notifiable / not_notifiable + risk to subjects
- `POST /breaches/{id}/queue-authority-notification` — generates the exact
  Art. 33(3) submission package (hashed, attached) and opens a **mandatory
  authenticated human task** (no supervisory-authority machine API exists)
- `POST /breaches/{id}/record-submission` — stores the exact submitted text,
  its hash, the submission timestamp and the authority reference, and
  completes the task with the authenticated actor
- `POST /breaches/{id}/record-receipt` — the ONLY path to
  `authority_acknowledged`; a receipt is mandatory (also enforced by a DB
  CHECK)
- `POST /breaches/{id}/queue-subject-notifications` — durable Art. 34 outbox
  for high-risk breaches
- `POST /breaches/{id}/record-subject-delivery` — delivery evidence required
  before a notification counts as sent
- `POST /breaches/{id}/resolve` — close (waits for all subject deliveries)

`BREACH_NOTIFICATION_EMAILS` is the DPO contact fallback used in the
submission package. Customer notification timing is governed by the DPA
("without undue delay"), not by this service.

## GDPR governance registry (ROPA/DPIA/TIA)

[`src/governance.rs`](src/governance.rs) seeds and serves the canonical
registry (migration 214): `processing_activities`, `lawful_basis_records`,
`dpia_assessments`, `subprocessor_contracts`,
`international_transfer_assessments`, `scc_records`, `adequacy_evidence` and
`retention_classes`.

What is seeded: the platform's data stores with purpose, subjects, data
categories, recipients, controller/processor role, retention class and a
`source_location` proving the record — plus the statutory retention classes
(Estonian accounting evidence, seven years) and the one subprocessor +
transfer the deployment configuration substantiates (AWS SES us-east-1).

What is deliberately left for Legal (never invented in code): every
lawful-basis record is `basis = NULL, basis_status = 'requires_legal_input'`;
the seeded DPIA screening is `status = 'required'`; transfer assessments are
`transfer_mechanism = 'undetermined'`. SCC records and adequacy evidence are
not seeded at all. `governance::approve_activity` refuses an activity whose
lawful basis is unresolved, and `governance::register_activity` refuses a new
store that does not identify all of the fields above.

## DSAR statutory clock

`data_subject_requests` carries the explicit clock (migration 213):
`received_at`, `identity_verified_at`, `statutory_due_at` (receipt + one
calendar month, Art. 12(3)), `extension_due_at`, `extension_reason` and
`extension_notified_at`. The due date is persisted at intake — not derived
from a configurable "N days" — and an extension (up to two further calendar
months) requires both a reason and a notification timestamp, enforced by
`GdprAutomation::extend_request` and a DB CHECK constraint.

## Erasure vs statutory retention

A customer erasure never deletes records under an independent legal-retention
obligation. Invoices are redacted of the subject's data and moved to the
legally-restricted archive with the monotonic lifecycle

```
product-active → legally-restricted → statutory expiry → deletion
```

(`src/legal_archive.rs`, table `legal_retention_archive`, trigger-enforced).
The DSAR result discloses what was retained, why, and until when
(`retained_disclosure`, mirrored on the deletion certificate).

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

DB-backed tests need `TEST_DATABASE_URL` (and `TEST_REDIS_URL` for the
queue/erasure tests); without them the tests skip.

The release tests in `tests/gdpr_governance_release_tests.rs` provision
databases from the REAL migration chain via `migrator::test_support`. The
DML-only boot test additionally creates a role and therefore needs
`TEST_DATABASE_ADMIN_URL` pointing at a connection with CREATEROLE (CI's
`TEST_DATABASE_URL` role is usually superuser and can be used as-is; locally
with a restrictive role, set e.g.
`TEST_DATABASE_ADMIN_URL=postgresql://postgres@localhost:5432/postgres`).
