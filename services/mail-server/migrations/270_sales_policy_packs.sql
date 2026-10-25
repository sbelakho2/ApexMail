-- Owner-approved autonomous-action policy packs (invariant I22).
--
-- An operator may flip a tenant to `autonomous_guarded`, but mode alone does
-- NOT authorize autonomous sends: the audit requires an ACTIVE, OWNER-APPROVED
-- policy pack that (a) covers the tenant, (b) enumerates the permitted action
-- kinds, and (c) caps the daily autonomous volume. Without a covering pack the
-- autonomy gate must refuse with `policy_pack_missing`.
--
-- "Owner-approved" is two columns that must BOTH be set (approved_by text and
-- approved_at timestamptz) plus an explicit active flag — the same shape the
-- counsel-approved jurisdiction policies use (migration 200). Approval never
-- expires silently: `expires_at` NULL means the pack stays active until an
-- operator deactivates it.

CREATE TABLE IF NOT EXISTS sales_policy_packs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           VARCHAR(26) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pack_name           VARCHAR(120) NOT NULL,
    -- The action kinds this pack authorizes for autonomous execution.
    -- CHECK-constrained to the known kinds so a typo cannot widen authority.
    actions             TEXT[] NOT NULL CHECK (
                            array_length(actions, 1) >= 1
                            AND actions <@ ARRAY[
                                'reply_autosend', 'sequence_send',
                                'calendar_book', 'research'
                            ]::text[]
                        ),
    daily_message_cap   INTEGER NOT NULL CHECK (daily_message_cap BETWEEN 1 AND 100000),
    monthly_message_cap INTEGER NOT NULL CHECK (monthly_message_cap BETWEEN 1 AND 1000000),
    active              BOOLEAN NOT NULL DEFAULT true,
    owner_approved_by   TEXT NOT NULL CHECK (owner_approved_by <> ''),
    owner_approved_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_sales_policy_packs_active_per_tenant
    ON sales_policy_packs (tenant_id)
    WHERE active;

CREATE INDEX IF NOT EXISTS idx_sales_policy_packs_tenant
    ON sales_policy_packs (tenant_id, active);

-- A tenant has AT MOST one active pack: the gate reads "the" pack, never a
-- priority list, so a partially-overlapping pair can never widen authority.
-- (Enforced by the partial unique index above; this trigger guards a rename
-- of the predicate.)
CREATE OR REPLACE FUNCTION sales_policy_packs_single_active() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.active AND EXISTS (
        SELECT 1 FROM sales_policy_packs
        WHERE tenant_id = NEW.tenant_id AND active AND id <> NEW.id
    ) THEN
        RAISE EXCEPTION 'tenant % already has an active policy pack', NEW.tenant_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sales_policy_packs_single_active ON sales_policy_packs;
CREATE TRIGGER trg_sales_policy_packs_single_active
    BEFORE INSERT OR UPDATE ON sales_policy_packs
    FOR EACH ROW EXECUTE FUNCTION sales_policy_packs_single_active();
