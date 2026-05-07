-- DI-002: Down migration for 202602260002_uid_backfill
--
-- DESTRUCTIVE — refuses to run unless `mailstore.allow_destructive_down='1'`.
-- Dropping `uid`/`uidnext` columns destroys IMAP UID state and breaks any
-- live mail clients. Operators must opt in explicitly.

DO $$
BEGIN
    IF current_setting('mailstore.allow_destructive_down', true) IS DISTINCT FROM '1' THEN
        RAISE EXCEPTION
            'Refusing destructive down migration. Set mailstore.allow_destructive_down=1 to confirm.';
    END IF;
END
$$;

-- Preserve column data in archive columns rather than dropping outright,
-- so an operator who set the GUC by mistake can still recover.
ALTER TABLE IF EXISTS mail_messages
    RENAME COLUMN uid TO uid_archived_pre_rollback;
ALTER TABLE IF EXISTS mail_mailboxes
    RENAME COLUMN uidnext TO uidnext_archived_pre_rollback;

