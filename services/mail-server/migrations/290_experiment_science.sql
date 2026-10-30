-- Migration 290: experiment science — one primary metric, frozen windows,
-- exposure-correct posteriors, guardrail pauses, holdouts, propensities and
-- the experiment registry.
-- =============================================================================
-- Audit SAI-2 (30 Oct): the bandit posterior was reward-weighted
-- (`alpha = 1 + sum(rewards)`, `beta = 1 + sum(|negative rewards|)`), so a
-- retained-MRR reward could move alpha by ln(1 + MRR/10) ≈ 6.9 for ONE
-- contact, silence never reached beta, and one contact's reply, meeting and
-- paid outcomes each moved the posterior. The owner's directive replaces
-- that model with ONE binary outcome per contact per arm:
--
--   positive reply or booked meeting within 14 days of the first touch
--
--   alpha = 1 + successes
--   beta  = 1 + (matured_contacts - successes)
--
-- A contact becomes a trial only when its observation window CLOSES
-- (matured); silence is a failure at window close. At most one success per
-- contact per arm: `sales_experiment_contact_trials` is the primary-outcome
-- ledger and its unique key is (experiment, arm, contact, metric, version).
-- Complaints, unsubscribes and bounces leave the posterior entirely and are
-- evaluated by the S2 guardrails. Revenue is kept OUT of the posterior: the
-- arm choice multiplies the Beta probability by an expected first-year value
-- derived deterministically from the realized revenue ledger.
--
-- This migration:
--   1. creates the metric registry (`sales_experiment_metrics`) and seeds the
--      primary metric, the north star and the three guardrails;
--   2. extends `sales_experiments` with the registry fields (hypothesis,
--      primary metric/version, planned sample, start/end, sequential method,
--      holdout share) and `sales_experiment_arms`/outcomes with the columns
--      the new write path needs;
--   3. creates the contact-trial ledger, the assignment/propensity ledger,
--      the arm+segment pause table and the holdout ledger;
--   4. RECOMPUTES every arm posterior from the historical ledger. The old
--      reward-weighted alpha/beta are never carried over: arms are rebuilt
--      from contact trials derived from `sales_experiment_outcomes` joined
--      to `sales_outcomes` on `outcome_key = 'sales-outcome:' || id`; an arm
--      whose legacy rows cannot be resolved to a contact is reset to the
--      Beta(1, 1) prior (a reward without a contact is not a trial);
--   5. proves the end state: every arm satisfies alpha = 1 + successes and
--      beta = 1 + (trials - successes), successes <= trials.
--
-- Idempotent by construction (IF NOT EXISTS / ON CONFLICT / guarded UPDATE).
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. The ONE metric registry. Every scoreboard read joins this table; a
--    metric whose definition is absent from the registry cannot be reported.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_experiment_metrics (
    metric_key   TEXT NOT NULL,
    version      INTEGER NOT NULL CHECK (version > 0),
    role         TEXT NOT NULL
        CHECK (role IN ('primary', 'north_star', 'guardrail')),
    definition   TEXT NOT NULL,
    window_days  INTEGER NOT NULL CHECK (window_days > 0),
    direction    TEXT NOT NULL DEFAULT 'higher_is_better'
        CHECK (direction IN ('higher_is_better', 'lower_is_better')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (metric_key, version)
);

INSERT INTO sales_experiment_metrics
    (metric_key, version, role, definition, window_days, direction)
VALUES
    ('positive_reply_or_meeting_14d', 1, 'primary',
     'A contact is a success when it produces a positive reply or a booked meeting within 14 days of its first touch. The outcome freezes at window close: a later reply does not change it. Silence is a failure at window close. One success per contact per arm.',
     14, 'higher_is_better'),
    ('won_mrr_per_1000_90d', 1, 'north_star',
     'Won MRR (trial, paid_subscription and retained_mrr value_eur) per 1,000 contacted accounts, measured 90 days after first touch. Computed from sales_outcomes through attribution; it is never folded into the arm posterior.',
     90, 'higher_is_better'),
    ('complaint_rate', 1, 'guardrail',
     'Complaints divided by contacted accounts (30-day window). An arm+segment at or above 0.1% is paused automatically.',
     30, 'lower_is_better'),
    ('unsubscribe_rate', 1, 'guardrail',
     'Unsubscribes divided by contacted accounts (30-day window). An arm+segment at or above 1% is paused automatically.',
     30, 'lower_is_better'),
    ('hard_bounce_rate', 1, 'guardrail',
     'Hard bounces divided by contacted accounts (30-day window). An arm+segment at or above 2% is paused automatically.',
     30, 'lower_is_better')
ON CONFLICT (metric_key, version) DO NOTHING;

COMMENT ON TABLE sales_experiment_metrics IS
    'The single experiment metric registry (S2): definition, version and frozen window per metric. The scoreboard joins this table instead of hard-coding definitions.';

-- ---------------------------------------------------------------------------
-- 2. Experiment registry fields (S5) and the per-segment holdout share (S3).
-- ---------------------------------------------------------------------------
ALTER TABLE sales_experiments
    ADD COLUMN IF NOT EXISTS hypothesis TEXT;
ALTER TABLE sales_experiments
    ADD COLUMN IF NOT EXISTS primary_metric TEXT NOT NULL
        DEFAULT 'positive_reply_or_meeting_14d';
ALTER TABLE sales_experiments
    ADD COLUMN IF NOT EXISTS primary_metric_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE sales_experiments
    ADD COLUMN IF NOT EXISTS planned_sample BIGINT
        CHECK (planned_sample IS NULL OR planned_sample > 0);
ALTER TABLE sales_experiments
    ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
ALTER TABLE sales_experiments
    ADD COLUMN IF NOT EXISTS ended_at TIMESTAMPTZ;
ALTER TABLE sales_experiments
    ADD COLUMN IF NOT EXISTS sequential_method TEXT NOT NULL DEFAULT 'msprt';
ALTER TABLE sales_experiments
    ADD COLUMN IF NOT EXISTS holdout_share DOUBLE PRECISION NOT NULL DEFAULT 0.05
        CHECK (holdout_share >= 0 AND holdout_share <= 0.5);

COMMENT ON COLUMN sales_experiments.hypothesis IS
    'The experiment registry hypothesis (S5); NULL only for legacy rows.';
COMMENT ON COLUMN sales_experiments.holdout_share IS
    'Per-segment randomized account-level holdout share (S3), stable hash of account id + segment + primary metric version. Default 5%, capped at 50%.';

-- ---------------------------------------------------------------------------
-- 3. The primary-outcome ledger: ONE row per (arm, contact, metric, version).
--    This is the idempotency key the S1 directive requires.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_experiment_contact_trials (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            TEXT NOT NULL,
    experiment_id        UUID NOT NULL REFERENCES sales_experiments(id) ON DELETE CASCADE,
    variant              TEXT NOT NULL,
    account_id           UUID,
    contact_id           UUID NOT NULL,
    segment              TEXT NOT NULL DEFAULT '',
    primary_metric       TEXT NOT NULL,
    primary_metric_version INTEGER NOT NULL CHECK (primary_metric_version > 0),
    first_touch_at       TIMESTAMPTZ NOT NULL,
    matures_at           TIMESTAMPTZ NOT NULL,
    success              BOOLEAN NOT NULL DEFAULT FALSE,
    matured_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (matures_at >= first_touch_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_sales_experiment_contact_trials_identity
    ON sales_experiment_contact_trials
       (experiment_id, variant, contact_id, primary_metric, primary_metric_version);
CREATE INDEX IF NOT EXISTS idx_sales_experiment_contact_trials_due
    ON sales_experiment_contact_trials (matures_at)
    WHERE matured_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sales_experiment_contact_trials_experiment
    ON sales_experiment_contact_trials (tenant_id, experiment_id, variant);

COMMENT ON TABLE sales_experiment_contact_trials IS
    'S1 primary-outcome ledger. A contact is a trial only once matured_at is set (window closed); success is frozen at that point. Unique key (experiment, arm, contact, metric, version) gives at most one success per contact.';

-- ---------------------------------------------------------------------------
-- 4. The event ledger gains the contact/tenant/kind/value columns the new
--    write path and the north-star metric need. It remains the append-only
--    audit trail keyed by outcome_key; the primary-outcome idempotency lives
--    in sales_experiment_contact_trials (above).
-- ---------------------------------------------------------------------------
ALTER TABLE sales_experiment_outcomes
    ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE sales_experiment_outcomes
    ADD COLUMN IF NOT EXISTS account_id UUID;
ALTER TABLE sales_experiment_outcomes
    ADD COLUMN IF NOT EXISTS contact_id UUID;
ALTER TABLE sales_experiment_outcomes
    ADD COLUMN IF NOT EXISTS segment TEXT NOT NULL DEFAULT '';
ALTER TABLE sales_experiment_outcomes
    ADD COLUMN IF NOT EXISTS kind TEXT;
ALTER TABLE sales_experiment_outcomes
    ADD COLUMN IF NOT EXISTS primary_metric TEXT;
ALTER TABLE sales_experiment_outcomes
    ADD COLUMN IF NOT EXISTS primary_metric_version INTEGER;
ALTER TABLE sales_experiment_outcomes
    ADD COLUMN IF NOT EXISTS value_eur NUMERIC(14, 4) NOT NULL DEFAULT 0;
ALTER TABLE sales_experiment_outcomes
    ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

UPDATE sales_experiment_outcomes l
SET tenant_id = e.tenant_id
FROM sales_experiments e
WHERE e.id = l.experiment_id AND l.tenant_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_sales_experiment_outcomes_tenant
    ON sales_experiment_outcomes (tenant_id, experiment_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_sales_experiment_outcomes_contact
    ON sales_experiment_outcomes (experiment_id, variant, contact_id)
    WHERE contact_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 5. Assignment/propensity ledger (S4): every arm decision logs the actual
--    probability the sampler used, plus the full propensity vector.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_experiment_assignments (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         TEXT NOT NULL,
    experiment_id     UUID NOT NULL REFERENCES sales_experiments(id) ON DELETE CASCADE,
    step_execution_id UUID,
    variant           TEXT NOT NULL,
    account_id        UUID,
    contact_id        UUID,
    segment           TEXT NOT NULL DEFAULT '',
    context_bucket    TEXT,
    propensity        DOUBLE PRECISION NOT NULL CHECK (propensity > 0 AND propensity <= 1),
    propensities      JSONB NOT NULL DEFAULT '{}'::jsonb,
    explore           BOOLEAN NOT NULL DEFAULT FALSE,
    decided_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_sales_experiment_assignments_step
    ON sales_experiment_assignments (step_execution_id)
    WHERE step_execution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sales_experiment_assignments_experiment
    ON sales_experiment_assignments (tenant_id, experiment_id, decided_at DESC);

COMMENT ON TABLE sales_experiment_assignments IS
    'S4 decision ledger: the ACTUAL probability each arm was chosen under (Thompson win probability), used by the IPS/SNIPS off-policy estimator.';

-- ---------------------------------------------------------------------------
-- 6. Guardrail pauses (S2): an arm+segment paused by a named threshold. The
--    bandit selection excludes paused arms; the pause is sticky until an
--    operator clears it.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_experiment_arm_pauses (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT NOT NULL,
    experiment_id UUID NOT NULL REFERENCES sales_experiments(id) ON DELETE CASCADE,
    variant       TEXT NOT NULL,
    segment       TEXT NOT NULL DEFAULT '',
    reason        TEXT NOT NULL,
    evidence      JSONB NOT NULL DEFAULT '{}'::jsonb,
    paused_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (experiment_id, variant, segment)
);

CREATE INDEX IF NOT EXISTS idx_sales_experiment_arm_pauses_tenant
    ON sales_experiment_arm_pauses (tenant_id, experiment_id);

COMMENT ON TABLE sales_experiment_arm_pauses IS
    'S2 guardrail pauses. Thresholds: complaint rate >= 0.1%, unsubscribe rate >= 1%, hard bounce rate >= 2%. The selection path refuses a paused arm; all arms paused suppresses the send.';

-- ---------------------------------------------------------------------------
-- 7. Randomized account-level holdout (S3): stable hash assignment.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sales_experiment_holdout_accounts (
    experiment_id    UUID NOT NULL REFERENCES sales_experiments(id) ON DELETE CASCADE,
    tenant_id        TEXT NOT NULL,
    account_id       UUID NOT NULL,
    segment          TEXT NOT NULL DEFAULT '',
    registry_version INTEGER NOT NULL CHECK (registry_version > 0),
    assigned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (experiment_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_sales_experiment_holdout_segment
    ON sales_experiment_holdout_accounts (tenant_id, experiment_id, segment);

COMMENT ON TABLE sales_experiment_holdout_accounts IS
    'S3 holdout: stable hash of account id + segment + primary metric version. Holdout accounts receive no sending for the life of the experiment; the scoreboard reports treatment-vs-holdout lift per segment.';

-- ---------------------------------------------------------------------------
-- 8. Propensity columns on the two assignment rows the send path persists.
-- ---------------------------------------------------------------------------
ALTER TABLE sales_step_executions
    ADD COLUMN IF NOT EXISTS arm_propensity DOUBLE PRECISION;
ALTER TABLE sales_enrollments
    ADD COLUMN IF NOT EXISTS arm_propensity DOUBLE PRECISION;

-- ---------------------------------------------------------------------------
-- 9. Data migration: rebuild contact trials from the historical ledger, then
--    RECOMPUTE the posteriors from them. The reward-weighted alpha/beta are
--    deliberately discarded: a reward row with no resolvable contact carries
--    no trial, so that arm resets to the Beta(1, 1) prior.
-- ---------------------------------------------------------------------------
WITH legacy AS (
    SELECT
        e.tenant_id,
        l.experiment_id,
        l.variant,
        o.contact_id,
        o.account_id,
        COALESCE(a.icp_segment, '') AS segment,
        o.occurred_at,
        o.outcome
    FROM sales_experiment_outcomes l
    JOIN sales_experiments e ON e.id = l.experiment_id
    JOIN sales_outcomes o
      ON l.outcome_key = 'sales-outcome:' || o.id::text
    LEFT JOIN sales_enrollments en ON en.id = o.enrollment_id
    LEFT JOIN sales_accounts a
      ON a.id = COALESCE(o.account_id, en.account_id)
    WHERE o.contact_id IS NOT NULL
),
grouped AS (
    SELECT
        tenant_id,
        experiment_id,
        variant,
        contact_id,
        MIN(occurred_at) AS first_touch_at,
        (ARRAY_AGG(account_id ORDER BY occurred_at)
            FILTER (WHERE account_id IS NOT NULL))[1] AS account_id,
        MIN(segment) AS segment
    FROM legacy
    GROUP BY tenant_id, experiment_id, variant, contact_id
),
successes AS (
    SELECT
        l.tenant_id,
        l.experiment_id,
        l.variant,
        l.contact_id,
        BOOL_OR(
            l.outcome IN ('positive_reply', 'meeting_booked')
            AND l.occurred_at <= g.first_touch_at + INTERVAL '14 days'
        ) AS success
    FROM legacy l
    JOIN grouped g
      ON g.tenant_id = l.tenant_id
     AND g.experiment_id = l.experiment_id
     AND g.variant = l.variant
     AND g.contact_id = l.contact_id
    GROUP BY l.tenant_id, l.experiment_id, l.variant, l.contact_id
)
INSERT INTO sales_experiment_contact_trials
    (tenant_id, experiment_id, variant, account_id, contact_id, segment,
     primary_metric, primary_metric_version, first_touch_at, matures_at,
     success, matured_at)
SELECT
    g.tenant_id,
    g.experiment_id,
    g.variant,
    g.account_id,
    g.contact_id,
    COALESCE(g.segment, ''),
    'positive_reply_or_meeting_14d',
    1,
    g.first_touch_at,
    g.first_touch_at + INTERVAL '14 days',
    COALESCE(s.success, FALSE),
    CASE WHEN g.first_touch_at + INTERVAL '14 days' <= NOW()
         THEN g.first_touch_at + INTERVAL '14 days'
         ELSE NULL END
FROM grouped g
JOIN successes s
  ON s.tenant_id = g.tenant_id
 AND s.experiment_id = g.experiment_id
 AND s.variant = g.variant
 AND s.contact_id = g.contact_id
ON CONFLICT (experiment_id, variant, contact_id, primary_metric, primary_metric_version)
DO NOTHING;

-- Recompute every arm that has trials: alpha = 1 + successes,
-- beta = 1 + (matured - successes), trials = matured, contacts = exposed.
UPDATE sales_experiment_arms a
SET trials = s.matured,
    successes = s.successes,
    alpha = 1.0 + s.successes,
    beta = 1.0 + (s.matured - s.successes),
    contacts = s.contacts,
    updated_at = NOW()
FROM (
    SELECT
        experiment_id,
        variant,
        COUNT(*) FILTER (WHERE matured_at IS NOT NULL)::bigint AS matured,
        COUNT(*) FILTER (WHERE matured_at IS NOT NULL AND success)::bigint AS successes,
        COUNT(*)::bigint AS contacts
    FROM sales_experiment_contact_trials
    GROUP BY experiment_id, variant
) s
WHERE a.experiment_id = s.experiment_id AND a.variant = s.variant;

-- Arms whose historical rewards cannot be resolved to a contact are NOT
-- trials. Reset them to the prior instead of carrying reward-weighted values.
UPDATE sales_experiment_arms a
SET alpha = 1.0,
    beta = 1.0,
    trials = 0,
    successes = 0,
    contacts = 0,
    updated_at = NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM sales_experiment_contact_trials t
    WHERE t.experiment_id = a.experiment_id AND t.variant = a.variant
);

-- The harm counter stays a guardrail telemetry counter, never a posterior move.
UPDATE sales_experiment_arms a
SET negative_outcomes = COALESCE(n.negative, 0)
FROM (
    SELECT experiment_id, variant, COUNT(*)::bigint AS negative
    FROM sales_experiment_outcomes
    WHERE reward < 0
    GROUP BY experiment_id, variant
) n
WHERE a.experiment_id = n.experiment_id AND a.variant = n.variant;

UPDATE sales_experiment_arms a
SET negative_outcomes = 0
WHERE NOT EXISTS (
    SELECT 1 FROM sales_experiment_outcomes l
    WHERE l.experiment_id = a.experiment_id AND l.variant = a.variant AND l.reward < 0
);

-- ---------------------------------------------------------------------------
-- 10. Proof: the exposure-correct model holds and the reward-weighted values
--     are gone.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    bad_count BIGINT;
    bad_example TEXT;
BEGIN
    SELECT COUNT(*), MIN(a.variant)
    INTO bad_count, bad_example
    FROM sales_experiment_arms a
    WHERE a.successes > a.trials
       OR ABS(a.alpha - (1.0 + a.successes)) > 1e-9
       OR ABS(a.beta - (1.0 + (a.trials - a.successes))) > 1e-9;

    IF bad_count > 0 THEN
        RAISE EXCEPTION
            'migration 290 proof failed: % arm(s) do not satisfy alpha=1+successes and beta=1+(trials-successes) (example variant: %)',
            bad_count, COALESCE(bad_example, '<unknown>');
    END IF;
END $$;
