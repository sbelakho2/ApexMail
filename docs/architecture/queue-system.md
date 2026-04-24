# Queue System Architecture

> **ApexMail** — PostgreSQL-native job queue with LISTEN/NOTIFY wakeups, batch processing, and multi-worker safety.
>
> **Implementation Note (2026-02):** Queue processing is implemented in Rust (`services/mail-server/crates/queue-provider/`). Historical browser-runtime pseudo-code was removed; interpret resource metrics in this document as Rust process metrics.

---

## Table of Contents

- [Overview](#overview)
- [Queue Backend — PostgreSQL](#queue-backend--postgresql)
- [Queue Tables](#queue-tables)
- [Dead Letter Queues](#dead-letter-queues)
- [Wakeup Mechanism — LISTEN/NOTIFY](#wakeup-mechanism--listennotify)
- [Stale Job Recovery (G-205)](#stale-job-recovery-g-205)
- [Multi-Worker Safety (G-223)](#multi-worker-safety-g-223)
- [Batch Processing Optimizations](#batch-processing-optimizations)
- [Adaptive Polling (C-108)](#adaptive-polling-c-108)
- [Worker Heartbeat (G-203)](#worker-heartbeat-g-203)
- [Visibility Timeout](#visibility-timeout)
- [Retry Strategies](#retry-strategies)

---

## Overview

ApexMail's queue system is built entirely on **PostgreSQL** — no external message broker (Redis, RabbitMQ, SQS) is required. This design eliminates an entire class of operational concerns (broker availability, message durability, network partitions between app and broker) while leveraging PostgreSQL's ACID guarantees for job state management.

The core primitive is `SELECT ... FOR UPDATE SKIP LOCKED`, which provides atomic, race-free job claiming in a single SQL statement.

---

## Queue Backend — PostgreSQL

### Why PostgreSQL?

| Concern               | PostgreSQL Queue                          | External Broker                        |
|-----------------------|-------------------------------------------|----------------------------------------|
| **Transactional safety** | Jobs and business data share a transaction | Two-phase commit or eventual consistency |
| **Operational complexity** | One system to back up, monitor, tune     | Additional infrastructure to manage    |
| **Exactly-once semantics** | Natural with `FOR UPDATE SKIP LOCKED`   | Requires idempotency layers            |
| **Durability**           | WAL-backed, same as any table            | Broker-specific persistence config     |

### Atomic Job Claiming

```sql
UPDATE email_queue
SET status = 'processing',
    worker_id = $1,
    started_at = NOW()
WHERE id = (
    SELECT id FROM email_queue
    WHERE status = 'pending'
      AND scheduled_for <= NOW()
    ORDER BY priority DESC, created_at ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING *;
```

**Key properties:**

- **No TOCTOU race** — The `SELECT` and `UPDATE` happen atomically. There is no window between "find a job" and "claim it" where another worker could claim the same job.
- **Priority ordering** — `ORDER BY priority DESC, created_at ASC` ensures high-priority jobs are processed first, with FIFO ordering within the same priority level.
- **Non-blocking** — `SKIP LOCKED` means workers never block on rows locked by other workers. If all available jobs are claimed, the query returns an empty result set immediately.

---

## Queue Tables

### email_queue

Primary queue for outbound email delivery.

| Parameter       | Value          |
|-----------------|----------------|
| **Concurrency** | 10 workers     |
| **Poll interval** | 1 second     |
| **Max retries** | 3              |
| **Retry delay** | 60 seconds     |
| **Visibility timeout** | 300 seconds |

```sql
CREATE TABLE email_queue (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    priority        INT NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending, processing, completed, failed, dead
    payload         JSONB NOT NULL,
    worker_id       TEXT,
    attempts        INT NOT NULL DEFAULT 0,
    max_attempts    INT NOT NULL DEFAULT 3,
    scheduled_for   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    failed_at       TIMESTAMPTZ,
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_queue_pending
    ON email_queue (priority DESC, created_at ASC)
    WHERE status = 'pending';
```

### webhook_queue

Queue for outbound webhook deliveries to customer endpoints.

| Parameter       | Value          |
|-----------------|----------------|
| **Concurrency** | 5 workers      |
| **Poll interval** | 1 second     |
| **Max retries** | 5              |
| **Retry delay** | 30 seconds     |

```sql
CREATE TABLE webhook_queue (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    endpoint_id     UUID NOT NULL,
    event_type      TEXT NOT NULL,
    priority        INT NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'pending',
    payload         JSONB NOT NULL,
    worker_id       TEXT,
    attempts        INT NOT NULL DEFAULT 0,
    max_attempts    INT NOT NULL DEFAULT 5,
    scheduled_for   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    failed_at       TIMESTAMPTZ,
    error           TEXT,
    response_status INT,
    response_body   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### analytics_queue

Batch-oriented queue for analytics event processing.

| Parameter       | Value          |
|-----------------|----------------|
| **Concurrency** | 2 workers      |
| **Poll interval** | 5 seconds    |
| **Batch size**  | 100            |
| **Retry delay** | 10 seconds     |

```sql
CREATE TABLE analytics_queue (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    event_type      TEXT NOT NULL,
    priority        INT NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'pending',
    payload         JSONB NOT NULL,
    worker_id       TEXT,
    attempts        INT NOT NULL DEFAULT 0,
    max_attempts    INT NOT NULL DEFAULT 3,
    scheduled_for   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## Dead Letter Queues

Jobs that exhaust all retry attempts are moved to dead letter queues for manual inspection and replay:

| Source Queue     | Dead Letter Queue |
|------------------|-------------------|
| `email_queue`    | `email_dlq`       |
| `webhook_queue`  | `webhook_dlq`     |

```sql
CREATE TABLE email_dlq (
    id              UUID PRIMARY KEY,
    original_id     UUID NOT NULL,
    tenant_id       UUID NOT NULL,
    payload         JSONB NOT NULL,
    error           TEXT NOT NULL,
    attempts        INT NOT NULL,
    failed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed        BOOLEAN NOT NULL DEFAULT FALSE,
    reviewed_by     TEXT,
    reviewed_at     TIMESTAMPTZ,
    replayed_at     TIMESTAMPTZ
);
```

**Dead letter queue workflow:**

1. Job exhausts `max_attempts` retries.
2. Job is `INSERT`ed into the DLQ with full payload and final error.
3. Original job status is set to `'dead'` in the source queue.
4. Operations team receives an alert (via observability/alerting).
5. After investigation, the job can be **replayed** (re-inserted into the source queue) or **acknowledged** (marked as reviewed).

---

## Wakeup Mechanism — LISTEN/NOTIFY

### Architecture

Instead of relying solely on periodic polling, the queue system uses PostgreSQL's `LISTEN/NOTIFY` mechanism for **instant job wakeups** via the `QueueNotifier` subsystem.

```
┌─────────────┐         pg_notify()         ┌──────────────┐
│  Producer    │ ──INSERT INTO queue──────→  │  PostgreSQL   │
│  (API/MTA)   │                             │  AFTER INSERT │
└─────────────┘                             │  TRIGGER      │
                                            └──────┬───────┘
                                                   │
                                          NOTIFY channel
                                                   │
                                            ┌──────▼───────┐
                                            │  Worker       │
                                            │  (LISTEN)     │
                                            └──────────────┘
```

### Trigger Setup

Each queue table has an `AFTER INSERT` trigger that calls `pg_notify()`:

```sql
CREATE OR REPLACE FUNCTION notify_queue_insert()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('queue_' || TG_TABLE_NAME, NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER email_queue_notify
    AFTER INSERT ON email_queue
    FOR EACH ROW EXECUTE FUNCTION notify_queue_insert();

CREATE TRIGGER webhook_queue_notify
    AFTER INSERT ON webhook_queue
    FOR EACH ROW EXECUTE FUNCTION notify_queue_insert();

CREATE TRIGGER analytics_queue_notify
    AFTER INSERT ON analytics_queue
    FOR EACH ROW EXECUTE FUNCTION notify_queue_insert();
```

### Notification Channels

| Queue Table       | NOTIFY Channel            |
|-------------------|---------------------------|
| `email_queue`     | `queue_email_queue`       |
| `webhook_queue`   | `queue_webhook_queue`     |
| `analytics_queue` | `queue_analytics_queue`   |

### Defensive Fallback

LISTEN/NOTIFY is a best-effort optimization. Notifications can be lost if:

- The LISTEN connection drops and is being re-established.
- PostgreSQL's notification queue overflows (8 GB limit, practically unreachable).
- The worker process restarts.

To handle these cases, **workers always fall back to periodic polling** after a configurable timeout. The NOTIFY mechanism reduces latency from `poll_interval` to near-zero under normal conditions, while polling guarantees no job is ever permanently missed.

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

---

## Stale Job Recovery (G-205)

### Problem

If a worker crashes mid-processing (OOM kill, hardware failure, network partition), the job it was processing remains in `'processing'` status indefinitely — an **orphaned job**.

### Solution

A recovery sweep runs **every 5 minutes** and resets jobs that have been stuck in `'processing'` for more than **30 minutes**:

```sql
UPDATE email_queue
SET status = 'pending',
    worker_id = NULL,
    started_at = NULL,
    attempts = attempts  -- preserve attempt count
WHERE status = 'processing'
  AND started_at < NOW() - INTERVAL '30 minutes'
RETURNING id;
```

**Design decisions:**

- **30-minute threshold** — Generous enough to avoid resetting legitimately slow jobs (large attachments, slow SMTP servers), aggressive enough to recover from crashes within a reasonable window.
- **Attempt count preserved** — The job's retry counter is not reset, preventing infinite retry loops on jobs that consistently crash workers.
- **Logged** — Every recovered job is logged with its original `worker_id` for post-mortem analysis.

---

## Multi-Worker Safety (G-223)

### No Double-Processing

The `FOR UPDATE SKIP LOCKED` clause is the sole mechanism that prevents double-processing. When multiple workers execute the claim query concurrently:

1. Worker A's `SELECT ... FOR UPDATE` locks row 1.
2. Worker B's `SELECT ... FOR UPDATE SKIP LOCKED` **skips** row 1 (it's locked) and locks row 2.
3. Both workers process different jobs. No coordination protocol is needed.

### Unique Worker IDs

Each worker process generates a unique identifier at startup:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

This ID is stored in the `worker_id` column when a job is claimed, enabling:

- **Debugging** — Trace which worker processed which job.
- **Stale job recovery** — Identify which worker failed when recovering orphaned jobs.
- **Metrics** — Per-worker throughput and error rate dashboards.

### No Shared Mutable State

Workers are fully independent processes with no shared mutable state:

- No in-memory locks or semaphores.
- No shared Redis locks for job coordination.
- No leader election for job assignment.
- Each worker maintains its own database connection pool.

The only shared resource is the PostgreSQL database itself, and all coordination happens through SQL-level locking.

---

## Batch Processing Optimizations

### Batch Completions (FIX-080)

Instead of updating each job's status individually after processing, completed jobs are **queued in memory** during a poll cycle and flushed in a **single PostgreSQL transaction**:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Multi-Row Operations via unnest()

Batch operations use PostgreSQL's `unnest()` to perform multi-row `UPDATE`, `INSERT`, and `DELETE` in a single statement:

```sql
-- Batch mark completed
UPDATE email_queue
SET status = 'completed',
    completed_at = NOW()
WHERE id = ANY(
    SELECT unnest($1::uuid[])
);

-- Batch insert into DLQ
INSERT INTO email_dlq (original_id, tenant_id, payload, error, attempts)
SELECT id, tenant_id, payload, error, attempts
FROM email_queue
WHERE id = ANY(SELECT unnest($1::uuid[]));
```

**Performance impact:** For a poll cycle that processes 10 jobs, this reduces database round-trips from 10+ individual `UPDATE` statements to a single batched `UPDATE` — a significant reduction in connection overhead and WAL writes.

### Graceful Degradation

If the batch flush fails (e.g., serialization error, connection timeout), the system **falls back to per-job processing**. Each job's status is updated individually, ensuring that a single problematic job does not prevent the rest from being marked complete.

---

## Adaptive Polling (C-108)

### Problem

Fixed-interval polling creates a trade-off: short intervals waste resources when the queue is empty, long intervals add latency when jobs arrive in bursts.

### Solution

After successfully processing one or more jobs in a poll cycle, the worker waits only **100 milliseconds** before polling again (instead of the full poll interval). This allows the worker to **drain the queue quickly** during bursts:

```
Queue state:  ████████░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░
Poll timing:  ╻╻╻╻╻╻╻╻·····················╻╻╻╻·····························
              ↑ 100ms gaps                   ↑ 100ms gaps
                         ↑ normal poll interval        ↑ normal poll interval
```

**Rules:**

| Condition                     | Next Poll Delay       |
|-------------------------------|-----------------------|
| Jobs processed this cycle     | 100 ms (fast drain)   |
| No jobs found                 | Full poll interval    |
| NOTIFY received               | Immediate             |

This adaptive behavior works in concert with LISTEN/NOTIFY wakeups. The NOTIFY provides instant reaction to new jobs, and adaptive polling ensures the queue drains efficiently once processing begins.

---

## Worker Heartbeat (G-203)

### Metrics Reported

Every **30 seconds**, each worker reports runtime health metrics:

| Metric             | Description                                    | Alert Threshold |
|--------------------|------------------------------------------------|-----------------|
| `memory_usage_pct` | Percentage of allocated heap used              | > 80%           |
| `heap_total`       | V8 heap total size (bytes)                     | —               |
| `heap_used`        | V8 heap used size (bytes)                      | —               |
| `event_loop_lag`   | Delay between scheduled and actual timer fire  | > 100 ms        |
| `active_jobs`      | Number of jobs currently being processed       | —               |
| `uptime_seconds`   | Worker process uptime                          | —               |

### Alert Conditions

| Condition                  | Severity | Action                                             |
|----------------------------|----------|----------------------------------------------------|
| Memory > 80%               | Warning  | Log warning, emit metric for dashboard             |
| Memory > 95%               | Critical | Graceful shutdown and restart                      |
| Event loop lag > 100 ms    | Warning  | Indicates CPU-bound work blocking the event loop   |
| Event loop lag > 500 ms    | Critical | Worker is unresponsive, force restart              |
| No heartbeat for 2 minutes | Critical | Worker presumed dead, trigger stale job recovery   |

---

## Visibility Timeout

### Purpose

The visibility timeout prevents a job from being **re-claimed by another worker** while it is still being processed by the original claimant. For `email_queue`, the visibility timeout is **300 seconds (5 minutes)**.

### How It Works

1. Worker A claims a job → `started_at = NOW()`, `status = 'processing'`.
2. While `NOW() - started_at < 300s`, the job is "invisible" to the claim query (the `WHERE status = 'pending'` clause excludes it).
3. If Worker A completes the job within 300 seconds → `status = 'completed'`.
4. If Worker A crashes and 300 seconds elapse → the stale job recovery sweep resets it to `'pending'`.

**Note:** The visibility timeout and stale job recovery threshold (30 minutes) are deliberately different. The visibility timeout is a conceptual window during which the job is exclusively owned. The stale recovery threshold is a conservative safety net that accounts for legitimately long-running jobs.

---

## Retry Strategies

### Email Queue — Exponential Backoff

```
Attempt 1:  30s  ×  2^0  =   30s delay
Attempt 2:  30s  ×  2^1  =   60s delay
Attempt 3:  30s  ×  2^2  =  120s delay
Attempt 4:  30s  ×  2^3  =  240s delay
...
Maximum delay capped at 30 minutes (1,800s)
```

Formula: `delay = min(30 × 2^(attempt - 1), 1800)` seconds.

The scheduled retry time is set via:

```sql
UPDATE email_queue
SET status = 'pending',
    scheduled_for = NOW() + (LEAST(30 * POWER(2, attempts - 1), 1800) || ' seconds')::interval,
    attempts = attempts + 1,
    error = $2
WHERE id = $1;
```

### Webhook Queue — Exponential Backoff with Retry-After

Webhook retries follow exponential backoff but also **respect the `Retry-After` HTTP header** from the receiving server:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

| Parameter          | Value                  |
|--------------------|------------------------|
| Base delay         | 30 seconds             |
| Backoff multiplier | 2×                     |
| Maximum delay      | 300 seconds (5 minutes)|
| Max retries        | 5                      |

### Webhook Auto-Disable

Webhook endpoints are automatically disabled when they consistently fail, protecting both ApexMail's resources and the receiving server:

| Trigger Condition                                          | Action                      |
|------------------------------------------------------------|-----------------------------|
| **10 consecutive failures** within a 1-hour window          | Endpoint disabled           |
| **> 50% failure rate** with ≥ 20 attempts in rolling window | Endpoint disabled           |

When an endpoint is disabled:

1. A `webhook.endpoint.disabled` event is emitted.
2. The tenant is notified via email and dashboard alert.
3. Pending webhook jobs for that endpoint are moved to the DLQ.
4. The endpoint can be **re-enabled manually** after the underlying issue is resolved.
5. On re-enable, a test webhook is sent to verify the endpoint is healthy before resuming delivery.
