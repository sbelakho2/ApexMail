-- Per-account delivery results for placement tests
CREATE TABLE IF NOT EXISTS placement_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_id         UUID NOT NULL REFERENCES placement_tests(id) ON DELETE CASCADE,
    seed_account_id UUID NOT NULL REFERENCES seed_accounts(id),
    inbox_type      VARCHAR(50),
    delivery_time_ms INTEGER,
    raw_headers     TEXT,
    spf_pass        BOOLEAN,
    dkim_pass       BOOLEAN,
    dmarc_pass      BOOLEAN,
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_placement_results_test ON placement_results (test_id);
CREATE INDEX IF NOT EXISTS idx_placement_results_account ON placement_results (seed_account_id);
