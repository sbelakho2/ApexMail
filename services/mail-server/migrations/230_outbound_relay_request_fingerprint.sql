-- Migration 230: outbound relay send_unit becomes payload-aware and
-- route-sticky (request fingerprint + typed idempotency conflict).
--
-- =============================================================================
-- `outbound_relay_ledger.send_unit` is the idempotency identity: a repeated
-- submission of the same key returns the stored outcome instead of
-- delivering twice. Until now the key alone carried that meaning — the same
-- send_unit presented with a DIFFERENT delivery contract (different
-- message bytes, envelope, recipients, or requested source IP) silently
-- inherited the historical row's state.
--
-- This migration adds:
--
--   request_fingerprint TEXT
--     H(tenant || envelope_from || canonical_recipients ||
--       message_sha256 || requested_source_ip)
--
-- stored on first claim. A later submission with the same send_unit but a
-- different fingerprint is a typed `IdempotencyConflict` (the relay raises
-- it; the caller must reconcile, never silently inherit). NULL marks rows
-- claimed before this migration: the first replay of such a row ADOPTS the
-- incoming fingerprint (pin-on-first-replay), after which the contract is
-- enforced.
--
-- Route stickiness is the same column in practice: the fingerprint includes
-- the requested source IP, so a worker that re-selected a different IP for
-- an in-flight unit gets the conflict and must reconcile against the
-- ORIGINAL route instead of re-routing under the same key.
--
-- Index: the fingerprint lookup happens by send_unit (the primary key), so
-- no additional index is needed; the column is here for the conflict check
-- and audit.
-- =============================================================================

ALTER TABLE outbound_relay_ledger
    ADD COLUMN IF NOT EXISTS request_fingerprint TEXT;

COMMENT ON COLUMN outbound_relay_ledger.request_fingerprint IS
    'H(tenant || envelope_from || canonical_recipients || message_sha256 || requested_source_ip) '
    'pinned on first claim (migration 230). A repeated send_unit with a different fingerprint is a '
    'typed IdempotencyConflict, never a silent inheritance of the stored state; NULL marks a row '
    'claimed before migration 230 whose fingerprint is pinned on first replay.';

-- Backfill is deliberately absent: recomputing the digest for existing rows
-- requires the message bytes in-process (canonical recipients + exact
-- envelope), which SQL cannot reproduce faithfully. Pin-on-first-replay is
-- the honest transition.
