-- Migration 234: server-side auth sessions for the retained auth-server
-- handlers (external-audit F3 remediation).
--
-- WHY: the retained auth-server login minted a DETERMINISTIC, purely
-- stateless token: `email:ts:SHA256(email:ts:secret)`. Zero randomness (two
-- logins in the same second produced byte-identical cookies) and zero
-- revocability — logout, password change, and MFA-reset could not invalidate
-- a leaked token, which stayed valid for its full 24h lifetime no matter
-- what. Verification is now server-side: the cookie carries a random
-- 256-bit session id (HMAC-bound to the process secret), and every
-- verification checks a row in THIS table that must be unrevoked and
-- unexpired.
--
-- Consumers (crates/auth-server/src/main.rs):
--   * mint   — INSERT one row per successful login/registration;
--   * verify — SELECT … WHERE id = $1 AND revoked_at IS NULL AND
--              expires_at > NOW() (fail-closed: a missing row denies);
--   * revoke — logout sets revoked_at on the row; password change / MFA
--     reset revoke every row of the user via idx_auth_sessions_user.
--
-- The table is deliberately minimal: no request metadata beyond the owning
-- user, so the status/auth binary never persists IPs or user agents here.

CREATE TABLE IF NOT EXISTS auth_sessions (
    -- The cookie value: 32 bytes from the OS CSPRNG, hex-encoded (64 chars).
    -- NOT a derivative of the email or any timestamp — sessions must be
    -- unfingerprintable and individually revocable.
    id          TEXT PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email       TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Hard expiry, mirrored from the cookie Max-Age (24h).
    expires_at  TIMESTAMPTZ NOT NULL,
    -- Set by logout / password change / MFA reset; verification requires
    -- revoked_at IS NULL.
    revoked_at  TIMESTAMPTZ
);

-- Revoking every session of a user (password change / MFA reset) is the
-- hot path besides verify.
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);
-- Expired/revoked rows are swept by expiry-aware queries; a partial index
-- on live sessions keeps verify cheap as the table grows.
CREATE INDEX IF NOT EXISTS idx_auth_sessions_live
    ON auth_sessions(expires_at)
    WHERE revoked_at IS NULL;
