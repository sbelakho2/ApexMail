-- 111: folded from crates/mailstore-core/migrations/202608080001_raw_message.sql (idempotent copy) —
-- the canonical chain owns the shared database's _sqlx_migrations; mailstore's
-- runtime auto-migrate is gated behind MAILSTORE_RUN_EMBEDDED_MIGRATIONS.
-- Add raw RFC5322 message bytes so IMAP FETCH BODY[] can return the exact
-- message as received/stored (previously only parsed text_body/html_body
-- were persisted, making full-message retrieval impossible).

ALTER TABLE mail_messages ADD COLUMN IF NOT EXISTS raw_message BYTEA;
