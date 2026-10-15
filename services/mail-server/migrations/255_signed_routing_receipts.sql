-- Migration 255: Signed routing receipts on the delivery acceptance ledger.
--
-- The sovereign promise "the proof is signed per message" needs more than a
-- ledger ROW: a row is only as trustworthy as the database that holds it. On
-- acceptance, the worker now signs a canonical payload over
-- (message_id, tenant_id, transport, accepted_at, actual_source_ip) with an
-- Ed25519 key (`RECEIPT_SIGNING_KEY`, mail-common::routing_receipt) and
-- stores the signature NEXT TO the ledger row, so a third party can verify
-- the acceptance without trusting this database, this API or this TLS stack:
--
--   * `receipt_payload`   — the exact canonical bytes that were signed
--                           (newline-delimited, version-tagged
--                           `apexmail-routing-receipt/v1`). Stored verbatim
--                           so verification never has to re-derive it.
--   * `receipt_signature` — base64 (standard, no padding) Ed25519 signature.
--   * `receipt_scheme`    — signature scheme label (`ed25519`).
--   * `receipt_key_id`    — hex(sha256(public_key))[..16], so a key rotation
--                           stays auditable.
--   * `receipt_signed_at` — when the signature was produced in the worker.
--
-- Fail-closed: the acceptance write REFUSES to mark a row `accepted` without
-- a signature ("no claim without evidence" — an unsigned receipt must not
-- silently exist), and the services refuse to boot in production without a
-- key. The four columns are therefore NULL only for historical rows written
-- before this migration.
--
-- Additive and idempotent: ADD COLUMN IF NOT EXISTS, no DML.
--
-- Public surfaces reading these columns: GET /v1/routing/receipts/public-key
-- and POST /v1/routing/receipts/verify (api-server, unauthenticated by
-- design).

ALTER TABLE sales_delivery_acceptances
    ADD COLUMN IF NOT EXISTS receipt_payload TEXT,
    ADD COLUMN IF NOT EXISTS receipt_signature TEXT,
    ADD COLUMN IF NOT EXISTS receipt_scheme TEXT,
    ADD COLUMN IF NOT EXISTS receipt_key_id TEXT,
    ADD COLUMN IF NOT EXISTS receipt_signed_at TIMESTAMPTZ;

COMMENT ON COLUMN sales_delivery_acceptances.receipt_payload IS
    'Exact canonical bytes signed at acceptance (apexmail-routing-receipt/v1, newline-delimited fields). Verbatim: verification must not re-derive it.';

COMMENT ON COLUMN sales_delivery_acceptances.receipt_signature IS
    'Base64 (standard, no padding) Ed25519 signature over receipt_payload. NULL only for rows accepted before migration 255.';

COMMENT ON COLUMN sales_delivery_acceptances.receipt_key_id IS
    'hex(sha256(public_key))[..16] of the signing key — lets an auditor select the right published key after a rotation.';
