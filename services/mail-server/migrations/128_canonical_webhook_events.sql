-- 128: canonical webhook event vocabulary (external review 2026-09-08 §7).
--
-- Exactly one namespace for message-scoped events: message.*. The legacy
-- email.* aliases and message.sent are retired; this migration rewrites
-- stored webhook subscriptions in place so existing integrations keep
-- receiving events under the canonical names.
--
-- Mapping:
--   email.sent       -> message.accepted
--   message.sent     -> message.accepted   ("sent" implied an SMTP attempt;
--                                              the event fires on API 202)
--   email.delivered  -> message.delivered
--   email.bounced    -> message.bounced
--   email.complained -> message.complained
--   email.opened     -> message.opened
--   email.clicked    -> message.clicked
--   bounce           -> message.bounced
--   complaint        -> message.complained

UPDATE webhooks
SET events = (
    SELECT COALESCE(jsonb_agg(DISTINCT
        CASE e
            WHEN 'email.sent'       THEN 'message.accepted'
            WHEN 'message.sent'     THEN 'message.accepted'
            WHEN 'email.delivered'  THEN 'message.delivered'
            WHEN 'email.bounced'    THEN 'message.bounced'
            WHEN 'email.complained' THEN 'message.complained'
            WHEN 'email.opened'     THEN 'message.opened'
            WHEN 'email.clicked'    THEN 'message.clicked'
            WHEN 'bounce'           THEN 'message.bounced'
            WHEN 'complaint'        THEN 'message.complained'
            ELSE e
        END
    ), '["*"]'::jsonb)
    FROM jsonb_array_elements_text(events) AS e
)
WHERE events::text <> '["*"]'::jsonb::text
  AND events::text ~ '"(email\.|message\.sent|bounce|complaint)';
