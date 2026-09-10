-- Migration 186: Recipient delivery state
--
-- F25/F75 (audit findings-2026-09-10): canonical per-recipient delivery
-- confirmation and the provider-message attribution index.
--
--   * email_queue.delivered_at — the CONFIRMED-delivery timestamp of ONE
--     recipient copy. `sent_at` keeps meaning "accepted by the provider"
--     (SMTP 250 / SES SendEmail 200); `delivered_at` is stamped only by a
--     provider delivery confirmation (SES Delivery event via
--     ses_notifications.rs). The two events are distinct and both
--     timestamps record their actual event time.
--   * messages.delivered_at — the parent aggregate, defined EXPLICITLY:
--     set once when EVERY recipient copy of the message is confirmed
--     delivered (all email_queue rows for the message terminal-sent with
--     delivered_at NOT NULL). Never set by a single-recipient callback.
--     The previous delivery callback wrote messages.delivered_at although
--     the column did not exist (SQLSTATE 42703).
--   * idx_email_queue_smtp_message_id — the durable provider-message
--     mapping: email_queue rows already persist the SES message id in
--     smtp_message_id at acceptance (handle_success). SES
--     bounce/complaint/delivery callbacks resolve tenant/message/recipient
--     EXCLUSIVELY through this stored mapping (F74) — never from raw
--     X-ApexMail-* headers. The index makes that resolution indexed.
--     Sends recorded before smtp_message_id existed (and SMTP sends, whose
--     bounces return via VERP, not SNS) have no mapping; those callbacks
--     are surfaced as unattributed (observable metric) instead of being
--     misattributed.

ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ;

ALTER TABLE messages ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ;

-- Provider-message mapping resolution (F74): SES event -> queue row.
CREATE INDEX IF NOT EXISTS idx_email_queue_smtp_message_id
    ON email_queue (smtp_message_id)
    WHERE smtp_message_id IS NOT NULL;
