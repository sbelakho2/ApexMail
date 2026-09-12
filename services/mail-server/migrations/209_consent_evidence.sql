-- Migration 209: Consent evidence for the sales legal gate
--
-- =============================================================================
-- Estonian Electronic Communications Act §103¹ (and the ePrivacy Art. 13
-- baseline it implements) requires prior consent for direct marketing to
-- natural persons. A boolean `consent_status` on a contact cannot demonstrate
-- that consent: the record has to carry the exact text the person agreed to,
-- its version, where it came from and when it was collected, and it has to be
-- possible to record (and honour) a withdrawal.
--
-- This table is the authoritative store the sales legal engine loads from.
-- `legal_policy::decide_with_state` treats it as follows:
--
--   * active evidence (withdrawn_at IS NULL) is the only thing that can
--     satisfy "prior consent" for a natural person;
--   * a withdrawn row (withdrawn_at IS NOT NULL) prohibits contact for BOTH
--     natural and legal persons until the person consents again;
--   * rows whose text/version/source/timestamps are not internally coherent
--     are ignored by the loader and therefore fail closed.
--
-- The table intentionally stores the consent text verbatim (versioned) rather
-- than a boolean so consent can be demonstrated later, not asserted. The
-- contact_point_id is nullable: consent can be person-level (NULL) or tied to
-- the channel endpoint it was collected for.
-- =============================================================================

CREATE TABLE IF NOT EXISTS sales_consent_evidence (
    id              UUID PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    contact_id      UUID REFERENCES sales_contacts(id) ON DELETE CASCADE,
    contact_point_id UUID REFERENCES sales_contact_points(id) ON DELETE SET NULL,
    -- The exact text the person agreed to, versioned, so consent can be
    -- demonstrated later rather than asserted.
    consent_text    TEXT NOT NULL,
    consent_version INTEGER NOT NULL CHECK (consent_version >= 1),
    source          TEXT NOT NULL,          -- form id, import id, ...
    collected_at    TIMESTAMPTZ NOT NULL,
    withdrawn_at    TIMESTAMPTZ,
    withdrawal_source TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_consent_evidence_contact
    ON sales_consent_evidence (tenant_id, contact_id, collected_at DESC);
