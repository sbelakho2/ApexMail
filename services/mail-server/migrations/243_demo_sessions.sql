-- Migration 243: screen-share demo sessions (SalesCloser plan §5.6)
--
-- A demo is a SCRIPTED, server-driven walkthrough: the presenter creates a
-- session from a named script, advances it step by step, and each step runs
-- REAL platform machinery (a rendered page, the API sandbox, the grader, the
-- pricing calculator, or a verifier-gated chat narration). The viewer sees
-- the steps and their live results through a token URL; a completed session
-- is replayable.
--
-- * demo_sessions — one presenter-run session. The viewer token is stored
--   HASHED (SHA-256): the plaintext is returned to the presenter exactly once
--   at creation, so a database read can never mint a viewer link. Expiry is
--   mandatory.
-- * demo_session_steps — the script's steps with their inputs and results.
--   `(session_id, idx)` is unique, so a replayed "advance" is a no-op rather
--   than a second execution: step execution is idempotent by construction.

CREATE TABLE IF NOT EXISTS demo_sessions (
    id          VARCHAR(26) PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    script_key  VARCHAR(64) NOT NULL,
    state       VARCHAR(16) NOT NULL DEFAULT 'created'
        CHECK (state IN ('created', 'running', 'completed', 'expired')),
    created_by  VARCHAR(64),
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_demo_sessions_expiry
    ON demo_sessions (expires_at)
    WHERE state IN ('created', 'running');

CREATE TABLE IF NOT EXISTS demo_session_steps (
    id          VARCHAR(26) PRIMARY KEY,
    session_id  VARCHAR(26) NOT NULL REFERENCES demo_sessions(id) ON DELETE CASCADE,
    idx         INT NOT NULL,
    kind        VARCHAR(32) NOT NULL
        CHECK (kind IN ('render_page', 'explorer_exec', 'grader', 'calculator', 'chat_narrate')),
    input       JSONB NOT NULL DEFAULT '{}'::jsonb,
    result      JSONB,
    ran_at      TIMESTAMPTZ,
    UNIQUE (session_id, idx)
);
