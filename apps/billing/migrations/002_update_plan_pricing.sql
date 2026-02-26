-- Migration: Update plan pricing
-- Date: 2026-02-04
-- Description: Correct pricing for Pro, Growth, Scale, and Enterprise plans
-- 
-- Canonical prices (docs/pricing.md):
-- - Pro: $65/mo
-- - Growth: $150/mo
-- - Scale: $350/mo
-- - Enterprise: $800/mo

BEGIN;

-- Update Pro plan pricing to $65/mo (6500 cents, 65000 yearly)
UPDATE plans SET 
  price_monthly = 6500,
  price_yearly = 6500 * 10,
  updated_at = NOW()
WHERE name = 'pro';

-- Update Growth plan pricing to $150/mo (15000 cents, 150000 yearly)
UPDATE plans SET 
  price_monthly = 15000,
  price_yearly = 15000 * 10,
  updated_at = NOW()
WHERE name = 'growth';

-- Update Scale plan pricing to $350/mo (35000 cents, 350000 yearly)
UPDATE plans SET 
  price_monthly = 35000,
  price_yearly = 35000 * 10,
  updated_at = NOW()
WHERE name = 'scale';

-- Update Enterprise plan pricing to $800/mo (80000 cents, 800000 yearly)
UPDATE plans SET 
  price_monthly = 80000,
  price_yearly = 80000 * 10,
  updated_at = NOW()
WHERE name = 'enterprise';

-- Log the pricing update for audit
-- NOTE: billing_audit_log columns are: tenant_id VARCHAR(26), action, actor_id, actor_type, details JSONB
INSERT INTO billing_audit_log (tenant_id, action, actor_id, actor_type, details)
SELECT 
  NULL,
  'pricing_update',
  gen_random_uuid(),
  'system',
  jsonb_build_object(
    'plan_id', id,
    'plan_name', name,
    'new_price_monthly', price_monthly,
    'new_price_yearly', price_yearly,
    'reason', 'Competitive pricing adjustment - Feb 2026'
  )
FROM plans 
WHERE name IN ('pro', 'growth', 'scale', 'enterprise');

COMMIT;
