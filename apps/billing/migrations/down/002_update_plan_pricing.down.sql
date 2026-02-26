BEGIN;

UPDATE plans SET
  price_monthly = 6500,
  price_yearly = 65000,
  updated_at = NOW()
WHERE name = 'pro';

UPDATE plans SET
  price_monthly = 15000,
  price_yearly = 150000,
  updated_at = NOW()
WHERE name = 'growth';

UPDATE plans SET
  price_monthly = 35000,
  price_yearly = 350000,
  updated_at = NOW()
WHERE name = 'scale';

UPDATE plans SET
  price_monthly = 80000,
  price_yearly = 800000,
  updated_at = NOW()
WHERE name = 'enterprise';

DELETE FROM billing_audit_log
WHERE action = 'pricing_update' AND actor_type = 'system';

COMMIT;
