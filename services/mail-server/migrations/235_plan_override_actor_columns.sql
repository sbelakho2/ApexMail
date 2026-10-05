-- Migration 235: widen plan_overrides actor columns
--
-- The admin plan-override route (POST /v1/billing/admin/tenants/:id/plan-override)
-- binds `admin_actor_id(&auth)` — the acting operator's user UUID (36 chars)
-- or the literal "system" — into `admin_id`. The column was created
-- VARCHAR(26) (069_create_missing_app_tables.sql), sized for slug ids, so
-- EVERY operator-initiated override failed with `value too long for type
-- character varying(26)` and surfaced as a 500. `overridden_by` has the same
-- sizing defect for any writer that stores a user id there.
--
-- VARCHAR(64) matches `stripe_subscriptions.admin_override_by`, the
-- pre-existing actor-attribution column for billing mutations.
ALTER TABLE plan_overrides ALTER COLUMN admin_id TYPE VARCHAR(64);
ALTER TABLE plan_overrides ALTER COLUMN overridden_by TYPE VARCHAR(64);
