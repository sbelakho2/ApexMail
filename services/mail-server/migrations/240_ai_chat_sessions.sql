-- Migration 240: console assistant sessions (SalesCloser plan §5.2)
--
-- The chat engine + `/v1/ai/chat` proxy already existed; what shipped with
-- this migration is the CONSOLE surface for them, with SERVER-SIDE session
-- storage instead of trusting a client-supplied history array.
--
-- * ai_chat_sessions — one conversation per (tenant, user), owned by the
--   console; the active session is the newest for the user.
-- * ai_chat_session_turns — the ordered turns. User turns are stored before
--   the model call so a failed answer never loses the question; the
--   assistant turn records the citations/escalation/docs_version the
--   verifier returned.
--
-- Retention: rows older than AI_CHAT_RETENTION_DAYS (90 by default) are
-- pruned by the api-server on session creation — the same window the
-- ai-service uses for `ai_chat_messages`, so both sides of the assistant's
-- memory expire together. Tenant scoping is enforced on every query; the
-- denormalized tenant_id on turns keeps tenant-scoped pruning and
-- cross-tenant probes single-table.
--
-- NOTE on numbering: the gap analysis wrote this as "233"; 233-239 are
-- taken by the SSO/session/campaign waves that landed first.

CREATE TABLE IF NOT EXISTS ai_chat_sessions (
    id          VARCHAR(26) PRIMARY KEY,
    tenant_id   VARCHAR(26) NOT NULL,
    user_id     VARCHAR(64) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_chat_sessions_owner
    ON ai_chat_sessions (tenant_id, user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS ai_chat_session_turns (
    id            VARCHAR(26) PRIMARY KEY,
    session_id    VARCHAR(26) NOT NULL REFERENCES ai_chat_sessions(id) ON DELETE CASCADE,
    tenant_id     VARCHAR(26) NOT NULL,
    role          VARCHAR(12) NOT NULL CHECK (role IN ('user', 'assistant')),
    content       TEXT NOT NULL,
    escalated     BOOLEAN NOT NULL DEFAULT FALSE,
    citations     JSONB NOT NULL DEFAULT '[]'::jsonb,
    docs_version  TEXT,
    disclosure    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_chat_session_turns_window
    ON ai_chat_session_turns (session_id, created_at);

CREATE INDEX IF NOT EXISTS idx_ai_chat_session_turns_tenant
    ON ai_chat_session_turns (tenant_id, created_at);
