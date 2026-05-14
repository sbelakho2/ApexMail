# ADR 0015: Email Worker Pipeline Architecture

**Status:** Accepted  
**Date:** 2026-03-15  
**Updated:** 2026-05-10  

## Context

ApexMail processes outgoing emails through a multi-stage worker pipeline. Emails submitted via the API are queued, enriched, delivered, and tracked through separate stages. The architecture needs to support both SES-based delivery (primary) and gRPC SMTP-based delivery (self-hosted/enterprise).

## Decision

The email worker pipeline uses two distinct queue backends, each serving a specific delivery path:

### 1. PostgreSQL-backed SES Queue (Primary)

- **Used for:** All shared-pool SES delivery (default for Free, Starter, Pro, Growth plans)
- **Queue mechanism:** PostgreSQL `LISTEN/NOTIFY` with a `sending_queue` table
- **Worker:** `outbound-queue` crate consumes messages, calls SES API via `ses-driver`
- **Retry:** Exponential backoff via `retry_at` column; dead-letter after 72 hours
- **Why PostgreSQL:** No additional infrastructure dependency; atomic enqueue+notify via same transaction as API request; consistent with the existing database architecture

### 2. gRPC SMTP Queue (Self-hosted / Enterprise)

- **Used for:** Tenant-dedicated IP delivery via Hetzner floating IPs
- **Queue mechanism:** Redis-backed work queue consumed by `smtp-edge` crate
- **Worker:** `smtp-edge` opens direct SMTP connections to destination MX servers
- **Why gRPC:** Enables streaming payload delivery (large attachments), backpressure-aware, and integrates with the existing observability framework via `tonic` middleware

### Pipeline Stages

```
API Submit → Validate → Enqueue → [Route Decision] → Deliver → Track
                ↑                      ↓
           PostgreSQL SES Queue   gRPC SMTP Queue (self-hosted)
```

| Stage | Component | Description |
|-------|-----------|-------------|
| Submit | `api-server` routes | HTTP POST /v1/messages validates and persists the message |
| Validate | `submission` crate | SPF/DKIM validation, content scanning, attachment size checks |
| Enqueue | `outbound-queue` crate | Writes to `sending_queue` table (SES) or Redis (SMTP) |
| Route Decision | Router logic | Checks tenant for dedicated IP ownership → SES or SMTP |
| Deliver | `ses-driver` / `smtp-edge` | Calls AWS SES API or opens SMTP connections |
| Track | `analytics` crate | Processes SES SNS notifications or SMTP delivery logs |

### Worker Scaling

- SES queue workers scale horizontally (multiple `outbound-queue` instances); PostgreSQL row-level locking prevents double-send
- SMTP queue workers are per-IP-pool; each `smtp-edge` instance binds to a specific floating IP for reputation management

## Consequences

### Positive

- Clear separation between SES and SMTP delivery paths
- No single queue infrastructure bottleneck
- PostgreSQL SES queue benefits from ACID guarantees for transactional reliability
- gRPC SMTP queue provides streaming and backpressure for large payloads

### Negative

- Two queue backends to maintain (PostgreSQL + Redis)
- Route decision logic adds latency on the enqueue path
- SMTP workers require floating IP orchestration

### References

- [ADR 0011: Dual Delivery (SES Primary)](0011-dual-delivery-ses-primary.md) — Rationale for SES-as-primary delivery
- [Architecture: Delivery Transport](../architecture/delivery-transport.md) — Detailed transport routing
- [Architecture: Queue System](../architecture/queue-system.md) — Queue architecture overview
- [`outbound-queue` crate](../../services/mail-server/crates/outbound-queue/) — SES queue worker implementation
- [`smtp-edge` crate](../../services/mail-server/crates/smtp-edge/) — SMTP delivery worker implementation
