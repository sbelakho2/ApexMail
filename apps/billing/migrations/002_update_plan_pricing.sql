-- Migration: Update plan pricing
-- Date: 2026-02-04
-- Description: Update pricing for Pro, Growth, Scale, and Enterprise plans
-- 
-- Price changes:
-- - Pro: $49 → $59
-- - Growth: $99 → $129  
-- - Scale: $299 → $399
-- - Enterprise: $999 → $1299

BEGIN;

-- Update Pro plan pricing (4900 → 5900 cents, 49000 → 59000 yearly)
UPDATE plans SET 
  price_monthly = 5900,
  price_yearly = 59000,
  updated_at = NOW()
WHERE name = 'pro';

-- Update Growth plan pricing (9900 → 12900 cents, 99000 → 129000 yearly)
UPDATE plans SET 
  price_monthly = 12900,
  price_yearly = 129000,
  updated_at = NOW()
WHERE name = 'growth';

-- Update Scale plan pricing (29900 → 39900 cents, 299000 → 399000 yearly)
UPDATE plans SET 
  price_monthly = 39900,
  price_yearly = 399000,
  updated_at = NOW()
WHERE name = 'scale';

-- Update Enterprise plan pricing (99900 → 129900 cents, 999000 → 1299000 yearly)
UPDATE plans SET 
  price_monthly = 129900,
  price_yearly = 1299000,
  updated_at = NOW()
WHERE name = 'enterprise';

-- Log the pricing update for audit
INSERT INTO billing_audit_log (tenant_id, action, resource_type, resource_id, details)
SELECT 
  '00000000-0000-0000-0000-000000000000'::uuid,
  'pricing_update',
  'plan',
  id,
  jsonb_build_object(
    'plan_name', name,
    'new_price_monthly', price_monthly,
    'new_price_yearly', price_yearly,
    'reason', 'Competitive pricing adjustment - Feb 2026'
  )
FROM plans 
WHERE name IN ('pro', 'growth', 'scale', 'enterprise');

COMMIT;
