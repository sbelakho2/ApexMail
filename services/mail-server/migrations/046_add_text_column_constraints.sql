-- Add length CHECK constraints to TEXT columns that represent bounded values.
-- 
-- Motivation:
--   TEXT columns lose database-level length validation. For subject lines (RFC 5321),
--   email addresses (RFC 5321), and display names, we want the database to enforce
--   maximum lengths rather than relying solely on application-level validation.
--
-- Strategy:
--   Constraints are added WITH `NOT VALID` to avoid long-running ACCESS EXCLUSIVE locks
--   on production tables. The VALIDATE CONSTRAINT step runs in a separate transaction
--   and only takes a SHARE UPDATE EXCLUSIVE lock (allowing concurrent reads/writes).
--
-- Pre-deployment data cleanup:
--   Before running this migration, ensure no existing rows exceed these limits:
--     SELECT COUNT(*) FROM email_queue WHERE char_length(subject) > 998;
--     SELECT COUNT(*) FROM mail_messages WHERE char_length(subject) > 998;
--     SELECT COUNT(*) FROM mail_accounts WHERE char_length(email) > 320;
--     SELECT COUNT(*) FROM mail_accounts WHERE char_length(display_name) > 255;
--   Any rows violating the constraints must be truncated before VALIDATE CONSTRAINT.

-- =============================================================================
-- Step 1: Add constraints with NOT VALID (fast, no long lock)
-- =============================================================================

-- email_queue.subject: RFC 5321 maximum of 998 characters per header line
ALTER TABLE email_queue 
    ADD CONSTRAINT chk_email_queue_subject_length 
    CHECK (char_length(subject) <= 998)
    NOT VALID;

-- mail_messages.subject: RFC 5321 maximum of 998 characters per header line
ALTER TABLE mail_messages 
    ADD CONSTRAINT chk_mail_messages_subject_length 
    CHECK (char_length(subject) <= 998)
    NOT VALID;

-- mail_accounts.email: RFC 5321 maximum of 320 characters (64@255)
ALTER TABLE mail_accounts 
    ADD CONSTRAINT chk_mail_accounts_email_length 
    CHECK (char_length(email) <= 320)
    NOT VALID;

-- mail_accounts.display_name: Common convention, 255 characters
ALTER TABLE mail_accounts 
    ADD CONSTRAINT chk_mail_accounts_display_name_length 
    CHECK (char_length(display_name) <= 255)
    NOT VALID;

-- =============================================================================
-- Step 2: Validate constraints (SHARE UPDATE EXCLUSIVE lock, non-blocking)
-- =============================================================================

-- H-04: Validate all NOT VALID constraints so they apply to existing rows too.
-- These use ALTER TABLE VALIDATE CONSTRAINT which only takes a SHARE UPDATE
-- EXCLUSIVE lock, allowing concurrent reads and writes during validation.
-- Pre-deployment data cleanup: run the COUNT queries from Step 1 comments.

DO $$
BEGIN
    BEGIN
        ALTER TABLE email_queue VALIDATE CONSTRAINT chk_email_queue_subject_length;
    EXCEPTION WHEN check_violation THEN
        RAISE WARNING 'email_queue.chk_email_queue_subject_length validation failed — found rows with subject > 998 chars';
    END;
    BEGIN
        ALTER TABLE mail_messages VALIDATE CONSTRAINT chk_mail_messages_subject_length;
    EXCEPTION WHEN check_violation THEN
        RAISE WARNING 'mail_messages.chk_mail_messages_subject_length validation failed — found rows with subject > 998 chars';
    END;
    BEGIN
        ALTER TABLE mail_accounts VALIDATE CONSTRAINT chk_mail_accounts_email_length;
    EXCEPTION WHEN check_violation THEN
        RAISE WARNING 'mail_accounts.chk_mail_accounts_email_length validation failed — found rows with email > 320 chars';
    END;
    BEGIN
        ALTER TABLE mail_accounts VALIDATE CONSTRAINT chk_mail_accounts_display_name_length;
    EXCEPTION WHEN check_violation THEN
        RAISE WARNING 'mail_accounts.chk_mail_accounts_display_name_length validation failed — found rows with display_name > 255 chars';
    END;
END;
$$;
