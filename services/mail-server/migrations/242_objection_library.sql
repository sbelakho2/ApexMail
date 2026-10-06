-- Migration 242: objection taxonomy + approved-response library (plan §5.5)
--
-- The objection ladder: a reply classified `not_interested` or `question`
-- carries an objection CLASS (price, timing, competitor, authority, trust,
-- need), and a grounded response is generated from an approved library entry
-- for that class plus the canonical facts.
--
-- * objection_library — owner/counsel-authored response guidance per class.
--   Approval is recorded the way jurisdiction policies record it
--   (approved_by + approved_at + validity window), so an unapproved or
--   expired entry is never usable. `evidence_ids` names the knowledge facts
--   the guidance rests on, and the CHECK below refuses an entry that may
--   appear in external copy without evidence: the library cannot become a
--   channel for unsupported claims.
-- * No entries are seeded here. The library is authored content: the plan's
--   rule is that a claim in customer copy carries evidence, and inventing
--   guidance in a migration would breach exactly that. The taxonomy itself is
--   code (ai-service reply_classify OBJECTION_CLASSES, mirrored by the
--   worker's classifier), and the CLASS CHECK keeps the two in step.

CREATE TABLE IF NOT EXISTS objection_library (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                 VARCHAR(26),          -- NULL = platform-wide entry
    objection_class           VARCHAR(16) NOT NULL
        CHECK (objection_class IN ('price', 'timing', 'competitor', 'authority', 'trust', 'need')),
    title                     VARCHAR(200) NOT NULL,
    response_guidance         TEXT NOT NULL,
    evidence_ids              JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_in_external_copy  BOOLEAN NOT NULL DEFAULT false,
    version                   INT NOT NULL DEFAULT 1,
    approved_by               TEXT,
    approved_at               TIMESTAMPTZ,
    valid_from                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until               TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- The claims gate at the schema level: an entry eligible for customer
    -- copy must name at least one piece of evidence.
    CONSTRAINT objection_library_evidence_required CHECK (
        NOT allowed_in_external_copy OR jsonb_array_length(evidence_ids) > 0
    )
);

CREATE INDEX IF NOT EXISTS idx_objection_library_lookup
    ON objection_library (objection_class, tenant_id, valid_from DESC);

-- The operational record of which class a reply carried: the worker's
-- classification row keeps its disposition, and the objection sub-label rides
-- alongside with the library entry that answered it (NULL when none did).
ALTER TABLE sales_reply_classifications
    ADD COLUMN IF NOT EXISTS objection_class VARCHAR(16),
    ADD COLUMN IF NOT EXISTS objection_library_id UUID;

CREATE INDEX IF NOT EXISTS idx_sales_reply_classifications_objection
    ON sales_reply_classifications (objection_class)
    WHERE objection_class IS NOT NULL;
