-- Migration 007: Create compatibility views for table name consistency
-- These views allow legacy code using old table names to continue working
-- while new code uses the canonical table names from migration 001

-- Code may reference 'subscriptions', but canonical table is 'stripe_subscriptions'
CREATE OR REPLACE VIEW subscriptions AS
SELECT * FROM stripe_subscriptions;

-- Code may reference 'usage_events', but canonical table is 'metering_events'  
CREATE OR REPLACE VIEW usage_events AS
SELECT * FROM metering_events;

-- Code may reference 'usage_thresholds', but canonical table is 'usage_alert_configs'
CREATE OR REPLACE VIEW usage_thresholds AS
SELECT * FROM usage_alert_configs;

-- Note: Code has been updated to use actual table/column names:
-- - stripe_subscriptions (not subscriptions)
-- - metering_events (not usage_events)
-- - usage_alert_configs (not usage_thresholds)
-- - wallets.reserved (not reserved_balance)
-- - usage_alert_configs.enabled (not is_enabled)
-- 
-- Views kept for backward compatibility with any remaining legacy references.
