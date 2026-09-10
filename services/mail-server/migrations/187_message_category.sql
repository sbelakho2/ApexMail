-- 187_message_category.sql
--
-- F55 (audit findings-2026-09-10): carry a validated, server-owned message
-- category through enqueue and dispatch so subscription_preferences can be
-- enforced alongside global suppression.
--
--   * messages.message_category / email_queue.message_category — the
--     category the SEND endpoint validated and normalized server-side
--     (apexmail_lib::email_headers::message_category::validate). Default
--     'marketing' for all legacy rows.
--   * Enforcement model (explicit):
--       - Global suppression (suppressions) applies to EVERY category,
--         including transactional/service mail.
--       - subscription_preferences rows with subscribed = false suppress
--         sends of that category, EXCEPT the transactional and service
--         categories — operational mail (invoices, password resets,
--         delivery notices) must reach the recipient even after a
--         marketing opt-out.
--   - The column width matches subscription_preferences.category
--     (VARCHAR(100)) so the two key spaces align.

ALTER TABLE messages ADD COLUMN IF NOT EXISTS message_category VARCHAR(100) NOT NULL DEFAULT 'marketing';

ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS message_category VARCHAR(100) NOT NULL DEFAULT 'marketing';

-- Dispatch-time category lookup (tenant + canonical recipient + category).
CREATE INDEX IF NOT EXISTS idx_sub_prefs_tenant_email_category
    ON subscription_preferences (tenant_id, email, category);
