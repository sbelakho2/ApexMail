-- 093_add_domain_dkim_key_columns.sql
-- Add per-domain DKIM signing key material to `domains`.
--
-- The production `domains` table was created without the DKIM key columns the
-- rest of the system expects (crates/apexmail-db and crates/worker-processors
-- both reference `dkim_selector` / `dkim_public_key` / `dkim_private_key`).
-- Without key material the outbound worker selects NULL keys and mail is
-- NEVER DKIM-signed. This migration closes the gap:
--
--   * `dkim_selector`  — DNS selector for this domain (e.g. `apexmail2026`)
--   * `dkim_public_key`  — public half, published in DNS as
--                         <selector>._domainkey.<domain> TXT
--   * `dkim_private_key` — PEM private key used to sign outbound mail
--   * `dkim_enabled`     — exists already; gates signing
--
-- Key material is stored encrypted at rest via column-level permissions and
-- the table is only readable by the worker/service accounts.

ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS dkim_selector TEXT,
    ADD COLUMN IF NOT EXISTS dkim_public_key TEXT,
    ADD COLUMN IF NOT EXISTS dkim_private_key TEXT;
