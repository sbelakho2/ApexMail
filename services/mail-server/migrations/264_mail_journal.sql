-- Migration 264: the Mailboxes archive + journaling legal copy.
--
-- The Mailboxes line is sold as "Archive + Journaling +€2 per seat" and the
-- per-seat `mail_accounts.archive_enabled` flag (migration 256) is billed,
-- but nothing ever copied a message to a journal destination. This table is
-- that destination: one immutable row per journaled message, written by the
-- outbound send effect and by the inbound mailbox-persistence path.
--
-- Design notes (deliberate):
--
--   * NO foreign key to `messages` / `email_queue` / `inbound_messages`.
--     The journal is the legal copy: it must OUTLIVE deletion of the live
--     message (retention expiry, GDPR erasure of the mailbox copy, queue
--     pruning), so a cascading FK would silently destroy the evidence.
--   * `raw_message` is the rendered RFC 5322 message (headers + body) as
--     BYTEA — the exact bytes accepted by the MTA / submitted to the
--     transport. TEXT would corrupt the legal copy: PostgreSQL TEXT cannot
--     store 0x00 and rejects non-UTF-8 MIME (8-bit bodies, legacy charsets),
--     so a TEXT column silently rewrites evidence.
--   * `to_addresses` is a JSONB array of envelope recipients (one entry for
--     the per-recipient outbound copy; the parsed header recipients for
--     inbound).
--   * `direction` is closed to 'inbound' / 'outbound'. Inbound identity is
--     one row per (inbound message, recipient mailbox) — keyed in
--     `source_table='mail_messages'`, `source_id=<mail_messages.id>` — so a
--     multi-recipient message that lands in N mailboxes journals N copies,
--     while an SMTP redelivery that dedups onto the same mailbox row adds
--     none.
--   * `source_table` / `source_id` are the provenance of the journaled
--     event ('email_queue' + queue row id for outbound). They are TEXT (not
--     UUID) because the live sources use both UUID and opaque ids.
--
-- Indexes: the retrieval surface is always tenant-scoped and newest-first
-- (`WHERE tenant_id = $1 ORDER BY journaled_at DESC, id DESC`), so the
-- composite (tenant_id, journaled_at DESC) index serves it directly. The
-- optional (tenant_id, message_id) index backs message-id correlation
-- lookups without a second scan.
--
-- Idempotency: `ux_mail_journal_source` makes (tenant, direction, source
-- table, source id) the journal identity, and the writer uses ON CONFLICT DO
-- NOTHING. A retried send that reaches the already-accepted path (or an
-- inbound store retry) therefore writes at most one legal copy per source
-- event instead of duplicating evidence.
--
-- Idempotent by construction (CREATE ... IF NOT EXISTS, no DML) so a re-run
-- on a current database no-ops cleanly.

CREATE TABLE IF NOT EXISTS mail_journal (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      VARCHAR NOT NULL,
    direction      VARCHAR NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    source_table   TEXT,
    source_id      TEXT,
    message_id     TEXT,
    from_address   TEXT,
    to_addresses   JSONB NOT NULL DEFAULT '[]'::jsonb,
    subject        TEXT,
    raw_message    BYTEA NOT NULL,
    journaled_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mail_journal_tenant_journaled_at
    ON mail_journal (tenant_id, journaled_at DESC);

CREATE INDEX IF NOT EXISTS idx_mail_journal_tenant_message_id
    ON mail_journal (tenant_id, message_id);

CREATE UNIQUE INDEX IF NOT EXISTS ux_mail_journal_source
    ON mail_journal (tenant_id, direction, source_table, source_id)
    WHERE source_id IS NOT NULL;
