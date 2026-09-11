-- 106: Login lookup functional indexes (audit item L-24) + missing
--      users.username column.
--
-- auth.rs resolves login accounts with:
--   SELECT ... FROM users
--   WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)
--
-- Two problems:
--   1. Neither predicate is indexable as written (functional,
--      case-insensitive): every login attempt was a full sequential scan of
--      users (L-24).
--   2. No migration in services/mail-server/migrations (nor tools/
--      migrations) ever created a users.username column — commit c62b1215
--      added the username branch to the query without schema. On any
--      database built from these migrations the login query failed outright
--      with 42703 (column "users.username" does not exist).
--
-- Fix: add the column (nullable — existing accounts have no username and
-- login-by-email is unaffected) plus functional indexes the planner can use
-- directly for the LOWER() predicates. No query change needed.
--
-- The indexes are plain CREATE INDEX (not CONCURRENTLY): repository
-- migrations execute inside a transaction, where CREATE INDEX CONCURRENTLY
-- is not permitted, and the users table is small enough that the brief
-- build lock is acceptable.
--
-- Deliberately NOT unique: users.email already carries a case-sensitive
-- UNIQUE constraint from migrations 052/056; a unique LOWER(email) index
-- could fail to build on legacy deployments holding case-differing
-- duplicates, and nothing in the application enforces case-insensitive
-- uniqueness of usernames today.

ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users (LOWER(email));

CREATE INDEX IF NOT EXISTS idx_users_username_lower ON users (LOWER(username));
