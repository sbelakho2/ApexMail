-- =============================================================================
-- 159: canonical reply analytics persistence (audit F67)
--
-- The analytics crate's ReplyTrackingService (reply_tracking.rs) ingests
-- reply events and aggregates reply metrics — but no migration ever created
-- reply_events, so every INSERT/SELECT failed at runtime and the separate
-- reply analytics had no canonical persistence: ingest silently dropped
-- events and get_metrics surfaced query errors instead of metrics.
--
-- This migration folds the canonical shape into the migration chain:
--   * tenant/message identity — external RFC 5322 Message-IDs are only ever
--     meaningful together with the owning tenant (tenant_id, message_id);
--   * event_id — idempotent event identity (SHA-256 over tenant + external
--     Message-ID, computed by the crate) so re-delivered webhook/ingress
--     duplicates collapse to one row via ON CONFLICT DO NOTHING;
--   * thread_depth — INTEGER (bounded by a CHECK); AVG() callers cast to
--     double precision in SQL;
--   * sentiment — stored as the bare enum variant label, not JSON.
--
-- Indexes cover the two access paths used by the crate:
--   * (tenant_id, timestamp DESC) — get_metrics window scans;
--   * (tenant_id, message_id)     — tenant-qualified thread-depth lookups.
-- =============================================================================

CREATE TABLE IF NOT EXISTS reply_events (
    id            BIGSERIAL PRIMARY KEY,
    event_id      VARCHAR(64)  NOT NULL,
    tenant_id     VARCHAR(26)  NOT NULL,
    message_id    TEXT         NOT NULL,
    in_reply_to   TEXT         NOT NULL DEFAULT '',
    recipient     VARCHAR(255) NOT NULL DEFAULT '',
    subject       TEXT         NOT NULL DEFAULT '',
    is_auto_reply BOOLEAN      NOT NULL DEFAULT FALSE,
    sentiment     VARCHAR(32)  NOT NULL DEFAULT 'Neutral',
    thread_depth  INTEGER      NOT NULL DEFAULT 0,
    timestamp     TIMESTAMPTZ  NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_reply_events_event_id UNIQUE (event_id),
    CONSTRAINT ck_reply_events_thread_depth_non_negative CHECK (thread_depth >= 0)
);

CREATE INDEX IF NOT EXISTS idx_reply_events_tenant_time
    ON reply_events (tenant_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_reply_events_tenant_message
    ON reply_events (tenant_id, message_id);
