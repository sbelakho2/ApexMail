-- DI-002: Down migration for 202602260001_init
--
-- DESTRUCTIVE — refuses to run unless the session-local GUC
-- `mailstore.allow_destructive_down = '1'` is set. The original version of
-- this file unconditionally `DROP TABLE … CASCADE` for the three core mail
-- tables, which is unrecoverable. For controlled rollbacks:
--
--   psql -c "SET mailstore.allow_destructive_down = '1'" \
--        -f 202602260001_init.down.sql
--
-- Preferred path is rename-then-archive (handled below) followed by a
-- separate manual cleanup after the retention window expires.

DO $$
BEGIN
    IF current_setting('mailstore.allow_destructive_down', true) IS DISTINCT FROM '1' THEN
        RAISE EXCEPTION
            'Refusing destructive down migration. Set mailstore.allow_destructive_down=1 to confirm.';
    END IF;
END
$$;

-- Archive-rename pattern: keeps data recoverable for one retention window.
-- A scheduled cleanup job is responsible for dropping the archive after the
-- documented retention period.
ALTER TABLE IF EXISTS mail_messages
    RENAME TO mail_messages_archive_pre_rollback;
ALTER TABLE IF EXISTS mail_mailboxes
    RENAME TO mail_mailboxes_archive_pre_rollback;
ALTER TABLE IF EXISTS mail_accounts
    RENAME TO mail_accounts_archive_pre_rollback;

