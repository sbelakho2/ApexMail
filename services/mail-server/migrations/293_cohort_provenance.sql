-- Migration 293: sales-science provenance and immutability.
-- =============================================================================
-- Audit 30 Oct (items 14, 15, 28, 29) found four defects the data model must
-- help make impossible:
--
--   14. holdout membership was RECOMPUTED from a hash (account | segment |
--       registry version) on every decision. An enrichment-driven segment
--       change flipped treatment -> holdout (or the reverse), contaminating
--       the randomization. The hash may decide the INITIAL assignment only;
--       from then on the persisted row is authoritative. Persisting only the
--       holdout branch was not enough (a treatment account could still flip
--       INTO the holdout later), so the ledger records BOTH branches.
--   15. `sequential_method` defaulted to the label of an anytime-valid test
--       the implementation never was. The code now ships an APPROXIMATE
--       normal sequential diagnostic that does not gate promotion; the
--       stored label is corrected here.
--   28. a Monte-Carlo propensity estimate with 0 wins logged an exact zero
--       propensity, which breaks IPS/SNIPS. The assignment ledger now stores
--       the win count / draw count / Monte-Carlo standard error / an
--       under-sampled flag for the logged decision, and the code floors the
--       logged propensity at a documented epsilon.
--   29. migration 290 rebuilt contact trials from legacy outcome data with an
--       INFERRED first touch, and those rows were indistinguishable from
--       native trials. `cohort_source` records the provenance; scoreboards
--       surface it.
--
-- Idempotent by construction (IF NOT EXISTS / guarded UPDATE / ON CONFLICT).
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Cohort provenance on the primary-outcome trial ledger.
--
--    'native'                the live send/outcome path observed the first
--                            touch (sales_step_executions.executed_at).
--    'reconstructed_legacy'  migration 290 rebuilt the trial from old outcome
--                            rows; first_touch_at is the EARLIEST RECOVERABLE
--                            outcome time, not a real first touch.
--
--    New rows default to 'native'; migration-290-era rows are marked in
--    section 2. The distinction is disclosed by the scoreboard and must be
--    carried into any dashboard.
-- ---------------------------------------------------------------------------
ALTER TABLE sales_experiment_contact_trials
    ADD COLUMN IF NOT EXISTS cohort_source TEXT NOT NULL DEFAULT 'native'
        CHECK (cohort_source IN ('native', 'reconstructed_legacy'));

CREATE INDEX IF NOT EXISTS idx_sales_experiment_contact_trials_cohort
    ON sales_experiment_contact_trials (tenant_id, experiment_id, cohort_source);

COMMENT ON COLUMN sales_experiment_contact_trials.cohort_source IS
    'native = the live send/outcome path observed the first touch; reconstructed_legacy = migration 290 rebuilt the trial from historical outcome rows and first_touch_at is the earliest recoverable outcome (an INFERRED first touch, not an observed one).';

-- ---------------------------------------------------------------------------
-- 2. One-shot marking of the migration-290 reconstruction.
--
--    A migration-290 trial is identifiable exactly: its first_touch_at is
--    MIN(sales_outcomes.occurred_at) over the legacy outcome rows linked by
--    `outcome_key = 'sales-outcome:' || id`, which is the grouping 290 used.
--    A native trial's first_touch_at is the step execution time, earlier than
--    its first outcome, so it does not match. This runs once; the column
--    default keeps every later row native.
-- ---------------------------------------------------------------------------
WITH legacy AS (
    SELECT
        l.experiment_id,
        l.variant,
        o.contact_id,
        MIN(o.occurred_at) AS first_touch_at
    FROM sales_experiment_outcomes l
    JOIN sales_outcomes o
      ON l.outcome_key = 'sales-outcome:' || o.id::text
    WHERE o.contact_id IS NOT NULL
    GROUP BY l.experiment_id, l.variant, o.contact_id
)
UPDATE sales_experiment_contact_trials t
SET cohort_source = 'reconstructed_legacy',
    updated_at = NOW()
FROM legacy g
WHERE t.experiment_id = g.experiment_id
  AND t.variant = g.variant
  AND t.contact_id = g.contact_id
  AND t.first_touch_at = g.first_touch_at
  AND t.cohort_source = 'native';

COMMENT ON TABLE sales_experiment_contact_trials IS
    'S1 primary-outcome ledger. A contact is a trial only once matured_at is set (window closed); success is frozen at that point. Unique key (experiment, arm, contact, metric, version) gives at most one success per contact. cohort_source distinguishes observed first touches from the migration-290 reconstruction.';

-- ---------------------------------------------------------------------------
-- 3. Immutable randomized membership.
--
--    `sales_experiment_holdout_accounts` was created (290) as the holdout
--    ledger, but membership must be persisted for TREATMENT accounts too:
--    otherwise a segment change can move a treatment account into the
--    holdout on a later hash. The table is therefore the membership ledger
--    for BOTH branches; only `assignment = 'holdout'` rows are held out and
--    only those rows enter the treatment-vs-holdout lift.
--
--    Existing rows predate the branch column and were written only for
--    holdout accounts, so the default 'holdout' is the truthful backfill.
-- ---------------------------------------------------------------------------
ALTER TABLE sales_experiment_holdout_accounts
    ADD COLUMN IF NOT EXISTS assignment TEXT NOT NULL DEFAULT 'holdout'
        CHECK (assignment IN ('holdout', 'treatment'));

COMMENT ON COLUMN sales_experiment_holdout_accounts.assignment IS
    'The persisted randomized branch: holdout receives no sending for the life of the experiment; treatment may be selected normally. The hash decides the INITIAL assignment only; an existing row is authoritative and is never recomputed.';

COMMENT ON TABLE sales_experiment_holdout_accounts IS
    'S3 randomized account-level membership ledger (created by migration 290, extended by 293). The stable hash of account id + segment + primary metric version decides the INITIAL branch; the persisted row (experiment_id, account_id) is authoritative for the life of the experiment, so a segment enrichment cannot flip membership. assignment = holdout means no sending; treatment is the ordinary arm path.';

-- ---------------------------------------------------------------------------
-- 4. Per-decision Monte-Carlo propensity diagnostics (S4).
--
--    The propensity is estimated from 2,000 Thompson draws. A rare arm can
--    win 0 draws, so the raw estimate is 0 although its true selection
--    probability is > 0; logging that exact zero breaks IPS/SNIPS. The
--    code logs a bounded estimate (>= PROPENSITY_FLOOR_EPSILON) and records,
--    with the logged propensity, the win count (the Monte-Carlo effective
--    sample size), the draw count, the standard error sqrt(p(1-p)/n) and an
--    under-sampled flag (wins = 0). Nullable for rows written before 293.
-- ---------------------------------------------------------------------------
ALTER TABLE sales_experiment_assignments
    ADD COLUMN IF NOT EXISTS propensity_wins BIGINT;
ALTER TABLE sales_experiment_assignments
    ADD COLUMN IF NOT EXISTS propensity_draws BIGINT;
ALTER TABLE sales_experiment_assignments
    ADD COLUMN IF NOT EXISTS propensity_standard_error DOUBLE PRECISION;
ALTER TABLE sales_experiment_assignments
    ADD COLUMN IF NOT EXISTS propensity_undersampled BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN sales_experiment_assignments.propensity_wins IS
    'Monte-Carlo win count behind the logged propensity (effective sample size of the estimate). 0 marks the false-exact-zero case the propensity floor and propensity_undersampled exist for.';
COMMENT ON COLUMN sales_experiment_assignments.propensity_draws IS
    'Monte-Carlo draw count behind the logged propensity (2000 in the production selection path).';
COMMENT ON COLUMN sales_experiment_assignments.propensity_standard_error IS
    'Monte-Carlo standard error sqrt(p_hat(1-p_hat)/n) of the logged (bounded) propensity estimate.';
COMMENT ON COLUMN sales_experiment_assignments.propensity_undersampled IS
    'TRUE when the Monte-Carlo estimate had 0 wins: the raw estimate is a false exact zero, so the logged propensity is the documented epsilon floor.';

COMMENT ON TABLE sales_experiment_assignments IS
    'S4 decision ledger: the ACTUAL probability each arm was chosen under (Thompson win probability), used by the IPS/SNIPS off-policy estimator. The propensity is a bounded Monte-Carlo estimate: propensity_wins/draws/standard_error/undersampled record its uncertainty, and the logged value is never below the documented epsilon.';

-- ---------------------------------------------------------------------------
-- 5. Honest sequential label.
--
--    The implementation is a normal-approximation sequential diagnostic with
--    plug-in variance. It is NOT an mSPRT, NOT anytime-valid and NOT a
--    promotion warrant, so no experiment may keep the old anytime-valid
--    label. The condition is deliberately literal-free: every label other
--    than the honest one is replaced.
-- ---------------------------------------------------------------------------
ALTER TABLE sales_experiments
    ALTER COLUMN sequential_method SET DEFAULT 'approximate_normal_sequential_diagnostic';

UPDATE sales_experiments
SET sequential_method = 'approximate_normal_sequential_diagnostic',
    updated_at = NOW()
WHERE sequential_method <> 'approximate_normal_sequential_diagnostic';

COMMENT ON COLUMN sales_experiments.sequential_method IS
    'The documented sequential method label. The implementation is an APPROXIMATE normal-approximation sequential diagnostic with plug-in variance: NOT anytime-valid, NOT an mSPRT and NOT a promotion warrant. Promotion requires the registered sample/credible-interval gate, never this diagnostic.';

-- ---------------------------------------------------------------------------
-- 6. Proof: the columns exist, every row carries a valid provenance/branch,
--    and no experiment keeps a non-honest sequential label.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    missing_columns BIGINT;
    bad_labels BIGINT;
BEGIN
    SELECT COUNT(*) INTO missing_columns
    FROM (VALUES
        ('sales_experiment_contact_trials', 'cohort_source'),
        ('sales_experiment_holdout_accounts', 'assignment'),
        ('sales_experiment_assignments', 'propensity_wins'),
        ('sales_experiment_assignments', 'propensity_draws'),
        ('sales_experiment_assignments', 'propensity_standard_error'),
        ('sales_experiment_assignments', 'propensity_undersampled')
    ) AS required(table_name, column_name)
    WHERE NOT EXISTS (
        SELECT 1 FROM information_schema.columns c
        WHERE c.table_schema = 'public'
          AND c.table_name = required.table_name
          AND c.column_name = required.column_name
    );

    IF missing_columns > 0 THEN
        RAISE EXCEPTION
            'migration 293 proof failed: % required column(s) missing', missing_columns;
    END IF;

    SELECT COUNT(*) INTO bad_labels
    FROM sales_experiments
    WHERE sequential_method <> 'approximate_normal_sequential_diagnostic';

    IF bad_labels > 0 THEN
        RAISE EXCEPTION
            'migration 293 proof failed: % experiment(s) still carry a non-honest sequential label',
            bad_labels;
    END IF;
END $$;
