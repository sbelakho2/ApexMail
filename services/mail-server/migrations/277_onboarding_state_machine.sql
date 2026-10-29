-- Migration 277: the onboarding state machine.
--
-- Sixth external audit #15 (half A): a new tenant walks invited →
-- configuring_domain → verifying_dns → sending_ready → active, with
-- `blocked` absorbing — and until now NOTHING tracked that walk. A tenant
-- that signed up, created a domain, verified DNS and sent its first
-- campaign looked byte-identical in `tenants` to one that signed up and
-- never came back: the console could not answer "you are here, do this
-- next", and support could not tell an onboarding stall from a workspace
-- that was simply suspended mid-flight.
--
-- Three columns on `tenants`:
--
--   onboarding_state      — the machine's current state, CHECK-pinned to
--                           exactly the six states `routes::onboarding`
--                           advances between (the schema is the backstop
--                           for every writer, including future ones).
--   onboarding_updated_at — when the state last moved (the read surface
--                           can answer "stale since when").
--   onboarding_note       — the Block bookkeeping: JSON `{"prior": "..."}`,
--                           the state `Unblock` restores. NULL on every
--                           un-blocked tenant.
--
-- Honest seeding BEFORE the constraint: every pre-existing tenant is
-- placed in the state its OWN history proves, never left to the default:
--
--   * a tenant with rows in `email_queue` HAS operated → 'active';
--   * a tenant whose status <> 'active' is a restricted workspace →
--     'blocked'. `blocked` is absorbing, so it is applied second and wins
--     over the operating verdict above: a suspended tenant is not
--     "onboarding-complete", it is blocked;
--   * everyone else stays the default 'invited'.
--
-- The seeding UPDATEs only ever touch rows the machine has not moved (on a
-- re-run: 'invited' rows for the operating verdict, anything not already
-- 'blocked' for the restricted verdict), so a re-run cannot stomp a state
-- the application advanced in the meantime.
--
-- NOT VALID + conditional VALIDATE (migration 273's proven pattern): a
-- deployment carrying a pre-fix row outside the vocabulary must not fail
-- the whole migration chain. New and updated rows are enforced
-- immediately; a clean table is validated inline, a dirty one raises a
-- WARNING naming the reconciliation step.
--
-- Idempotent: the ADD COLUMNs are IF NOT EXISTS, the seeding is
-- self-guarding as above, and the constraint is checked by name before it
-- is added. Safe to re-run on any deployment (the repo's migration
-- convention).
-- =============================================================================

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS onboarding_state TEXT NOT NULL DEFAULT 'invited';
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS onboarding_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS onboarding_note TEXT;

-- ---------------------------------------------------------------------------
-- Honest seeding: place every pre-existing tenant where its own history
-- says it is. Restricted status wins (blocked is absorbing); the operating
-- verdict applies to the rest.
-- ---------------------------------------------------------------------------
UPDATE tenants
   SET onboarding_state = 'active'
 WHERE onboarding_state = 'invited'
   AND EXISTS (
       SELECT 1 FROM email_queue
       WHERE email_queue.tenant_id = tenants.id
   );

UPDATE tenants
   SET onboarding_state = 'blocked'
 WHERE status <> 'active'
   AND onboarding_state <> 'blocked';

-- ---------------------------------------------------------------------------
-- The vocabulary CHECK: NOT VALID on add (273's pattern), then validate
-- inline when the table is clean, warn-and-leave when it is not.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    cname CONSTANT TEXT := 'chk_tenants_onboarding_state';
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = cname
          AND conrelid = 'public.tenants'::regclass
    ) THEN
        ALTER TABLE tenants
            ADD CONSTRAINT chk_tenants_onboarding_state
            CHECK (onboarding_state IN (
                'invited',
                'configuring_domain',
                'verifying_dns',
                'sending_ready',
                'active',
                'blocked'
            ))
            NOT VALID;
    END IF;

    BEGIN
        IF EXISTS (
            SELECT 1 FROM tenants
            WHERE onboarding_state IS NULL
               OR onboarding_state NOT IN (
                   'invited',
                   'configuring_domain',
                   'verifying_dns',
                   'sending_ready',
                   'active',
                   'blocked'
               )
            LIMIT 1
        ) THEN
            RAISE WARNING 'tenants contains onboarding_state values outside the onboarding machine vocabulary; chk_tenants_onboarding_state left NOT VALID, reconcile the rows and run ALTER TABLE tenants VALIDATE CONSTRAINT chk_tenants_onboarding_state';
        ELSE
            ALTER TABLE tenants VALIDATE CONSTRAINT chk_tenants_onboarding_state;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            RAISE WARNING 'could not validate chk_tenants_onboarding_state on tenants: %', SQLERRM;
    END;
END
$$;

COMMENT ON COLUMN tenants.onboarding_state IS
    'Onboarding machine state (migration 277): invited, configuring_domain, verifying_dns, sending_ready, active, blocked (absorbing). Advanced only through routes::onboarding::advance_persisted.';
COMMENT ON COLUMN tenants.onboarding_updated_at IS
    'When onboarding_state last moved (migration 277).';
COMMENT ON COLUMN tenants.onboarding_note IS
    'Block bookkeeping (migration 277): JSON {"prior": "<state>"} recorded when the machine entered blocked, consumed (cleared) by Unblock to restore that state. NULL on every un-blocked tenant.';
