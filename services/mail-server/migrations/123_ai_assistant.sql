-- Migration 123: AI assistant storage — grounded docs index + chat audit + email-agent
-- claim disambiguation.
--
-- ai_docs_chunks: the assistant's knowledge index over the repo's own docs.
--   Shared public knowledge (tenant scope 'public'); a per-tenant scope is
--   reserved for future tenant-specific grounding. Full-text search today;
--   the embedding column is provisioned so vector hybrid search activates
--   without a further migration once an embeddings runtime exists.
--
-- ai_chat_messages: every customer-facing AI interaction, tenant-scoped,
--   with citations and escalation state — the audit + GDPR surface.
--
-- inbound_messages.ai_claimed_at: the email agent claims rows independently
--   of the reply-handler's `processing` column; a shared eligibility
--   predicate with different claim semantics raced the two consumers.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS ai_docs_chunks (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_scope   VARCHAR(26) NOT NULL DEFAULT 'public',
    docs_version   TEXT        NOT NULL,
    path           TEXT        NOT NULL,
    title          TEXT        NOT NULL,
    locale         VARCHAR(5)  NOT NULL DEFAULT 'en',
    chunk_index    INT         NOT NULL,
    content        TEXT        NOT NULL,
    content_tsv    TSVECTOR    GENERATED ALWAYS AS (to_tsvector('english', content)) STORED,
    -- Provisioned for hybrid vector search (populated when an embeddings
    -- runtime is configured); NULL until then.
    embedding      DOUBLE PRECISION[],
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_scope, path, chunk_index, docs_version)
);

CREATE INDEX IF NOT EXISTS idx_ai_docs_chunks_tsv
    ON ai_docs_chunks USING GIN (content_tsv);
CREATE INDEX IF NOT EXISTS idx_ai_docs_chunks_trgm
    ON ai_docs_chunks USING GIN (content gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_ai_docs_chunks_scope
    ON ai_docs_chunks (tenant_scope, docs_version);

CREATE TABLE IF NOT EXISTS ai_chat_messages (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    VARCHAR(26) NOT NULL,
    user_id      VARCHAR(64) NOT NULL,
    role         VARCHAR(12) NOT NULL CHECK (role IN ('user','assistant')),
    content      TEXT        NOT NULL,
    citations    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    escalated    BOOLEAN     NOT NULL DEFAULT false,
    model        TEXT,
    docs_version TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_chat_messages_tenant_time
    ON ai_chat_messages (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_chat_messages_user
    ON ai_chat_messages (user_id, created_at DESC);

ALTER TABLE inbound_messages
    ADD COLUMN IF NOT EXISTS ai_claimed_at TIMESTAMPTZ;
