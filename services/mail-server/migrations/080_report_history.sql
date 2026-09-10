-- Migration 080: Automated report generation — report_history table.
--
-- Stores generated daily/weekly/monthly reports for admin download.

CREATE TABLE IF NOT EXISTS report_history (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type     VARCHAR(20) NOT NULL
        CHECK (report_type IN ('daily', 'weekly', 'monthly')),
    format          VARCHAR(10) NOT NULL
        CHECK (format IN ('json', 'csv', 'pdf')),
    period_start    TIMESTAMPTZ NOT NULL,
    period_end      TIMESTAMPTZ NOT NULL,
    data            JSONB,
    file_path       TEXT,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_report_history_type_time
    ON report_history (report_type, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_report_history_generated_at
    ON report_history (generated_at DESC);
