-- Migration 258: CAPTCHA/challenge readiness for the sales scraping engine.
--
-- The owner's plan closes with "vastly improved scraping, all CAPTCHA-ready".
-- The engine's fetch path could not tell a challenge page from data: a 403 was
-- reported as a credentials problem, a 429 as a rate limit, and a 200
-- challenge shell was fed to the JSON parser (or read as an empty result).
-- This migration lands the STORAGE for the fix; the classification itself
-- lives in `sales-autopilot/src/discovery/fetch.rs` (deterministic marker
-- detection) and never parses a blocked body.
--
--   1. `sales_scrape_blocked_sources` — the persisted blocked-source queue.
--      One row per (tenant, source, url) with the evidence an operator needs
--      to act: classification (blocked_captcha | blocked_policy |
--      blocked_transient), HTTP status, the challenge markers that matched,
--      a bounded human detail, Retry-After, and the occurrence counter.
--      Deliberately CHECK-FREE: the classification vocabulary and the review
--      states are owned by the code that writes them (a new challenge vendor
--      marker must not require a schema change); unknown values are rejected
--      by the typed writer, not by the database.
--   2. `sales_scrape_host_health` — the persistent per-host politeness and
--      health state: consecutive blocks, the backoff window
--      (`blocked_until`), last classification/status, last success, and the
--      operator's per-host solver opt-in. The in-process registry enforces
--      it; this table is what makes it survive a restart and what the admin
--      surface reads.
--   3. `sales_scrape_solver_audit` — every solve attempt, including the ones
--      that never left the process (hook disabled, host not opted in, host in
--      backoff). NO cookie/token material is stored: only whether a token was
--      received and what happened on the single retry.
--   4. `sales_source_runs.status` gains the three blocked classifications so
--      a blocked source run is visible in the run ledger instead of being
--      flattened into 'failed'. Widening only: no existing row can violate
--      the new predicate.
--   5. `sales_discovery_candidates.contact_email` + `.fetched_at` — the data
--      quality extension: a normalized contact email (when a source yields
--      one) and the time the EVIDENCE was fetched (distinct from
--      `discovered_at`, the row's insert time; equal for rows written before
--      this migration, which is the truthful backfill).
--
-- Idempotent by construction: guarded DDL, IF NOT EXISTS, and the one DML
-- statement is scoped to `WHERE fetched_at IS NULL`.

-- ---------------------------------------------------------------------------
-- 1. Blocked-source queue.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_scrape_blocked_sources (
    id               UUID        PRIMARY KEY,
    tenant_id        TEXT        NOT NULL,
    source           TEXT        NOT NULL,
    url              TEXT        NOT NULL,
    host             TEXT        NOT NULL,
    classification   TEXT        NOT NULL,
    http_status      INTEGER,
    markers          TEXT[]      NOT NULL DEFAULT '{}',
    detail           TEXT,
    retry_after      TIMESTAMPTZ,
    occurrences      BIGINT      NOT NULL DEFAULT 1,
    state            TEXT        NOT NULL DEFAULT 'open',
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_job_id      UUID        REFERENCES sales_discovery_jobs(id) ON DELETE SET NULL,
    reviewed_by      TEXT,
    reviewed_at      TIMESTAMPTZ,
    review_note      TEXT,
    UNIQUE (tenant_id, source, url)
);

CREATE INDEX IF NOT EXISTS idx_sales_scrape_blocked_open
    ON sales_scrape_blocked_sources (tenant_id, state, last_seen_at DESC);

-- ---------------------------------------------------------------------------
-- 2. Per-host health, backoff and the solver opt-in.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_scrape_host_health (
    tenant_id           TEXT        NOT NULL,
    host                TEXT        NOT NULL,
    consecutive_blocks  INTEGER     NOT NULL DEFAULT 0,
    total_blocks        BIGINT      NOT NULL DEFAULT 0,
    last_classification TEXT,
    last_status         INTEGER,
    last_blocked_at     TIMESTAMPTZ,
    last_success_at     TIMESTAMPTZ,
    blocked_until       TIMESTAMPTZ,
    solver_enabled      BOOLEAN     NOT NULL DEFAULT FALSE,
    solver_enabled_at   TIMESTAMPTZ,
    solver_enabled_by   TEXT,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, host)
);

-- ---------------------------------------------------------------------------
-- 3. Solver audit trail (no secret material).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_scrape_solver_audit (
    id                    UUID        PRIMARY KEY,
    tenant_id             TEXT        NOT NULL,
    blocked_source_id     UUID        REFERENCES sales_scrape_blocked_sources(id) ON DELETE SET NULL,
    host                  TEXT        NOT NULL,
    url                   TEXT        NOT NULL,
    outcome               TEXT        NOT NULL,
    detail                TEXT,
    solver_latency_ms     BIGINT,
    token_received        BOOLEAN     NOT NULL DEFAULT FALSE,
    retried               BOOLEAN     NOT NULL DEFAULT FALSE,
    retry_classification  TEXT,
    retry_http_status     INTEGER,
    attempted_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_scrape_solver_audit
    ON sales_scrape_solver_audit (tenant_id, attempted_at DESC);

-- ---------------------------------------------------------------------------
-- 4. A blocked source run is a distinct status, not 'failed'.
-- ---------------------------------------------------------------------------
ALTER TABLE sales_source_runs
    DROP CONSTRAINT IF EXISTS sales_source_runs_status_check;
ALTER TABLE sales_source_runs
    ADD CONSTRAINT sales_source_runs_status_check
    CHECK (status IN ('running', 'succeeded', 'failed', 'rate_limited',
                      'blocked_captcha', 'blocked_policy', 'blocked_transient'));

-- ---------------------------------------------------------------------------
-- 5. Candidate data quality: normalized contact email + evidence fetch time.
-- ---------------------------------------------------------------------------
ALTER TABLE sales_discovery_candidates
    ADD COLUMN IF NOT EXISTS contact_email TEXT;
ALTER TABLE sales_discovery_candidates
    ADD COLUMN IF NOT EXISTS fetched_at TIMESTAMPTZ;

-- Backfill: for a row written before this migration the row's insert time IS
-- the best available statement of when the evidence was fetched.
UPDATE sales_discovery_candidates
    SET fetched_at = discovered_at
    WHERE fetched_at IS NULL;

ALTER TABLE sales_discovery_candidates
    ALTER COLUMN fetched_at SET DEFAULT NOW();
ALTER TABLE sales_discovery_candidates
    ALTER COLUMN fetched_at SET NOT NULL;
