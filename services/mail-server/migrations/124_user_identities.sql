-- Migration 124: SSO identity links — (provider, subject) → user binding.
--
-- SSO login previously resolved accounts purely by email. On GitHub the
-- top-level profile email is a public, settable, UNVERIFIED field, so an
-- attacker who set their public GitHub email to a victim's address was
-- logged into the victim's account at the next callback (full-repo audit
-- 1.2, P0). user_identities binds one external identity to exactly one
-- local user and is the PRIMARY resolution key in routes/sso.rs:
--
--   * login looks up (provider, subject) FIRST — a returning IdP user
--     reaches their account even if the IdP-side email changed, and a
--     changed email can never re-point the link at another account;
--   * email match survives only as the FIRST-link fallback and is
--     restricted to IdP-verified addresses; the link row is written in
--     the same flow that first matched the user;
--   * ON DELETE CASCADE keeps links consistent with user deletion, so a
--     present link always resolves to a live user row.
--
-- email_at_link records the (verified) address at link time for audit;
-- it is informational only and never participates in matching.
--
-- subject is the IdP's stable account id (GitHub numeric user id, Google
-- `sub` claim) — never an email address.

CREATE TABLE IF NOT EXISTS user_identities (
    provider       VARCHAR(32)  NOT NULL,
    subject        VARCHAR(255) NOT NULL,
    user_id        UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email_at_link  VARCHAR(320),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, subject)
);

-- Reverse lookup for account-settings / unlink flows: which identities a
-- user has linked. The forward lookup is served by the primary key.
CREATE INDEX IF NOT EXISTS idx_user_identities_user
    ON user_identities (user_id);
