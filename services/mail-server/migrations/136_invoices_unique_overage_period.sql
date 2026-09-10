-- Migration 136: one usage invoice per (tenant, period) (audit F29).
--
-- The overage sweep's advisory-lock claim committed BEFORE the invoice
-- INSERT ran on a separate connection, so two sweeps could both pass the
-- marker check and double-invoice the same period. The sweep now claims
-- and inserts in ONE transaction; this unique index is the schema-level
-- backstop. Reconcile pre-existing duplicates first, conservatively: the
-- EARLIEST invoice per (tenant, marker) keeps the marker (it is the
-- original billing of the period); later duplicates keep their row —
-- financial records are never deleted — but lose the marker so the index
-- can exist. They are NOTICEd for operator review/voiding.

DO $$
DECLARE
    dup RECORD;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'uq_invoices_tenant_overage_period'
    ) THEN
        FOR dup IN
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY tenant_id, overage_period
                       ORDER BY issued_at NULLS LAST, created_at, id
                   ) AS dup_rank
            FROM invoices
            WHERE overage_period IS NOT NULL
        LOOP
            IF dup.dup_rank > 1 THEN
                UPDATE invoices
                SET overage_period = NULL, updated_at = NOW()
                WHERE id = dup.id;
                RAISE NOTICE '136: duplicate usage invoice % cleared its overage_period marker (rank %) — operator should void/refund if it was collected', dup.id, dup.dup_rank;
            END IF;
        END LOOP;
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_invoices_tenant_overage_period
    ON invoices (tenant_id, overage_period)
    WHERE overage_period IS NOT NULL;
