-- 251: the 2026-10-07 gates-review fixes, applied as a FORWARD migration.
--
-- Context (deploy 2026-10-13): the review fixed two REAL data-logic bugs by
-- editing migrations that had ALREADY been applied to production (002/110's
-- uidnext recomputation and 127's retry-ladder matcher). Editing an applied
-- migration diverges a migrated database from a fresh chain and breaks the
-- sqlx ledger checksum; the audited remedy is to keep the corrected files
-- (fresh databases get the fixed logic directly; the production ledger's
-- checksums for those six files were repaired under a backed-up ledger,
-- each change verified safe for an already-migrated database) and ship the
-- DATA-affecting half of each fix FORWARD here. Both statements are
-- idempotent: they converge a migrated database to the same end state the
-- corrected chain produces on a fresh one.

-- UIDNEXT must be NON-DECREASING (RFC 3501): a mailbox whose highest-UID
-- message was expunged has uidnext > max(uid)+1, and the pre-fix statement
-- recomputed it downward, telling cached clients deliveries were lost and
-- permitting UID reuse after expunge. GREATEST guard, applied to every
-- mailbox that could have been lowered by the old logic.
UPDATE mail_mailboxes mb
SET uidnext = GREATEST(mb.uidnext, COALESCE((
    SELECT MAX(uid) + 1 FROM mail_messages mm WHERE mm.mailbox_id = mb.id
), 1))
WHERE mb.uidnext IS DISTINCT FROM GREATEST(mb.uidnext, COALESCE((
    SELECT MAX(uid) + 1 FROM mail_messages mm WHERE mm.mailbox_id = mb.id
), 1));

-- The retry-ladder matcher treated `{}` policies as satisfied (NULL::int < 10
-- is NULL) and aborted on non-numeric casts; the corrected matcher raises
-- numeric policies below 10, adopts `{}`, and leaves non-numeric values
-- untouched.
UPDATE webhooks
SET retry_policy = jsonb_set(
        jsonb_set(COALESCE(retry_policy, '{}'::jsonb), '{maxRetries}', '10'),
        '{retryDelay}', '30'
    )
WHERE COALESCE(retry_policy->>'maxRetries', '0') ~ '^[0-9]+$'
  AND COALESCE(retry_policy->>'maxRetries', '0')::int < 10;
