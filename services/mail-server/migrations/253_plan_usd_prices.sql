-- Migration 253: the owner's 2026-10-15 price table — `plans` rows carry
-- the published USD list price alongside the EUR price the Adyen checkout
-- charges. Forward-only: no applied migration is edited; this file adds the
-- two additive columns and backfills the canonical values that
-- `platform-catalog` (`price_monthly_usd_cents` / `price_yearly_usd_cents`),
-- the billing seeds (`PlanSeed::price_monthly_usd` / `price_yearly_usd`) and
-- the boot reconcile all agree on.
--
-- Value provenance: the owner's price table (Developer 20/20, Pro 89/99,
-- Growth 229/249, Business 699/749, Enterprise Cloud 1,750/1,950 EUR/USD;
-- Free and PAYG 0). Annual USD is 10 monthly payments, the same rule as the
-- EUR ladder. Cents, matching `price_monthly` / `price_yearly`.
--
-- Re-run safety: both ALTERs are guarded (the 232/252 idiom), the backfill
-- is absolute (not incremental), so a partially applied run can be repeated;
-- the migrator's ledger still treats the file as applied exactly once.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. The two additive columns (NOT NULL DEFAULT 0 so every existing
--    INSERT ... without them keeps working).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'plans'
                     AND column_name = 'price_monthly_usd') THEN
        ALTER TABLE plans ADD COLUMN price_monthly_usd BIGINT NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = 'plans'
                     AND column_name = 'price_yearly_usd') THEN
        ALTER TABLE plans ADD COLUMN price_yearly_usd BIGINT NOT NULL DEFAULT 0;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Backfill the owner's table (USD cents). Absolute values: idempotent.
-- ---------------------------------------------------------------------------
UPDATE plans AS p
   SET price_monthly_usd = v.monthly_usd,
       price_yearly_usd  = v.yearly_usd,
       updated_at        = NOW()
  FROM (VALUES
        ('free',        0,         0),
        ('starter',     2000,      20000),
        ('pro',         9900,      99000),
        ('growth',      24900,     249000),
        ('scale',       74900,     749000),
        ('enterprise',  195000,    1950000),
        ('payg',        0,         0)
       ) AS v(name, monthly_usd, yearly_usd)
 WHERE p.name = v.name;

-- ---------------------------------------------------------------------------
-- 3. Non-catalog rows (operator-created plans) keep the 0 default; the
--    USD columns are catalog facts for catalog plans, and the boot
--    reconcile (`reconcile_plans_with_catalog`) forces the seeded values
--    onto the seven catalog rows.
-- ---------------------------------------------------------------------------
COMMENT ON COLUMN plans.price_monthly_usd IS
    'Published monthly USD list price in cents (mirrors platform-catalog price_monthly_usd_cents; the checkout still charges the EUR price_monthly).';
COMMENT ON COLUMN plans.price_yearly_usd IS
    'Published annual USD list price in cents = 10 monthly payments (mirrors platform-catalog price_yearly_usd_cents).';
