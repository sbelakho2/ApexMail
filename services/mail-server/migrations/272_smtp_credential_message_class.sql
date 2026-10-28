-- Migration 272: the SMTP submission credential carries a server-owned
-- message class.
--
-- Fifth external audit Tier-0 (P0): transactional SMTP was rejected as
-- marketing. The submission AUTH path authenticates a `users` row (the only
-- credential row it loads; `smtp_credentials` is a legacy table no code
-- reads), and the queue's category was decided by a hardcoded policy default
-- of `marketing`. A password-reset/2FA/receipt submitted over SMTP to a
-- recipient without marketing consent was therefore refused with
-- `550 5.7.1 marketing consent required`, breaking the advertised
-- transactional-SMTP product.
--
-- The class is an attribute of the AUTHENTICATED CREDENTIAL, never of the
-- message: a customer MIME header can never choose it. The vocabulary is the
-- existing `message_category` one (`apexmail_lib::email_headers`):
-- 'marketing', 'transactional' and 'service'. The conservative default is
-- 'marketing' (the non-preference-exempt class): every pre-existing
-- credential keeps today's legal behaviour until an operator deliberately
-- creates a transactional/service credential.
--
-- Deliberate creation: there is no SMTP-credential creation API or console
-- form in this repository today (users are provisioned by signup/SCIM and
-- authenticate on submission with their password). This migration is the
-- schema half; an operator marks a credential transactional only by an
-- explicit write to `users.message_class`, never by a customer-controlled
-- request field. If a credential-management surface is added later it must
-- expose this column as an explicit, admin-gated choice.
--
-- Idempotent and guarded: the column add and the constraint add are both
-- IF-NOT-EXISTS; the constraint is added NOT VALID and validated only when
-- existing rows already satisfy it, so a deployment with a hand-set bad value
-- is surfaced (WARNING) instead of failing the whole migration chain.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'users'
          AND column_name = 'message_class'
    ) THEN
        ALTER TABLE users ADD COLUMN message_class TEXT NOT NULL DEFAULT 'marketing';
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_users_message_class'
          AND conrelid = 'users'::regclass
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT chk_users_message_class
            CHECK (message_class IN ('marketing', 'transactional', 'service'))
            NOT VALID;
    END IF;

    -- Validate the new constraint when the data already satisfies it. A
    -- legacy hand-written value outside the vocabulary is left unvalidated
    -- (new rows are still enforced by the NOT VALID constraint) and named in
    -- the warning for operator reconciliation.
    IF NOT EXISTS (
        SELECT 1 FROM users
        WHERE message_class NOT IN ('marketing', 'transactional', 'service')
    ) THEN
        ALTER TABLE users VALIDATE CONSTRAINT chk_users_message_class;
    ELSE
        RAISE WARNING 'users.message_class contains values outside (marketing, transactional, service); constraint chk_users_message_class left NOT VALID, reconcile the rows and run ALTER TABLE users VALIDATE CONSTRAINT chk_users_message_class';
    END IF;
END
$$;
