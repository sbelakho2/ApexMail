-- Migration 223: sales_leads becomes a derived, read-only VIEW
--
-- =============================================================================
-- Final item of the "sales_leads -> account/contact" migration audit. Every
-- runtime writer already wrote the canonical account/contact model and then
-- inserted/updated/deleted a "compatibility" sales_leads row next to it; this
-- migration removes that stored table entirely. From here on `sales_leads` is
-- a view derived from:
--
--   * `sales_contacts`            — the person (the lead's identity)
--   * `sales_accounts`            — the company
--   * `sales_contact_points`      — the reachable email address
--   * `sales_enrollments`         — live outreach state feeding `status`
--
-- ID MAPPING (ids stay stable; this is the core of the migration)
-- ---------------------------------------------------------------------------
-- `sales_contacts.legacy_lead_id` (TEXT) carries the id the old table held.
-- It is uniqueness-checked per tenant:
--
--   CREATE UNIQUE INDEX idx_sales_contacts_tenant_legacy_lead_id
--       ON sales_contacts (tenant_id, legacy_lead_id);
--
-- so an id that a client, `inbound_messages.lead_id`, `sales_conversions`
-- or a CP URL still holds resolves, through the view, to exactly the same
-- canonical account/contact the old row was linked to (or to the account
-- resolved from the old row's normalized domain when the old `account_id` was
-- NULL/dangling; the old contact is resolved from `contact_id` when valid, the
-- address's `sales_contact_points` owner when not).
--
-- Lead-only columns with no canonical home yet are stored on `sales_contacts`
-- with a `lead_` prefix and projected back by the view under their original
-- names:
--
--   legacy_lead_id        -> id
--   legacy_lead_email     -> email / contact_email (fallback only; the
--                            canonical contact point always wins when present)
--   lead_source           -> source
--   lead_score            -> score
--   lead_notes            -> notes
--   lead_tags             -> tags
--   lead_deal_value       -> deal_value
--   lead_snoozed_until    -> snoozed_until
--   lead_last_reply_at    -> last_reply_at
--   lead_priority         -> priority
--   lead_created_at       -> created_at (preserves the old row's timestamp)
--   lead_updated_at       -> updated_at
--
-- `company_name`, `domain`, `contact_name`, `title`, `contact_email`, `email`
-- and `status` are derived: `sales_accounts.company/domain`,
-- `sales_contacts.full_name/job_title`, the primary email contact point, and
-- the same canonical lifecycle CASE the CP read already used
-- (`CANONICAL_LEAD_CTE`), respectively. `company` is backfilled onto the
-- resolved account when the account was created by this migration, and an
-- empty `sales_contacts.full_name` is filled from the old `contact_name`;
-- otherwise canonical data wins, exactly as the pre-view read already did.
--
-- INDEX MAPPING
-- ---------------------------------------------------------------------------
--   idx_sales_leads_tenant_email (UNIQUE tenant, lower(contact_email))
--       -> sales_contact_points' existing UNIQUE (tenant_id, channel,
--          normalized_value) plus create_lead's re-expressed duplicate check
--          (advisory-locked, canonical tables only). A view cannot carry a
--          unique index; the canonical side cannot hold a second contact
--          point for the same (tenant, email), which is the same guarantee
--          for a lead: one lead per tenant + email.
--   idx_sales_leads_fts_gin (GIN to_tsvector(name || email || company))
--       -> idx_sales_contacts_lead_search_gin on the trigger-maintained
--          `sales_contacts.lead_search_vector` column, built from exactly the
--          same expression. The search query is re-expressed against
--          `sales_contacts` so the index is actually usable.
--   idx_sales_leads_status / idx_sales_leads_status_created
--       -> no equivalent: `status` is DERIVED, not stored, so it cannot be
--          indexed. Tenant-scoped lifecycle indexes already exist on
--          `sales_contacts` and `sales_accounts`.
--   idx_sales_leads_tenant / account / contact
--       -> idx_sales_contacts_tenant_legacy_lead_id (unique above) covers the
--          tenant+id access path; `sales_contacts.account_id` already has
--          idx_sales_contacts_account.
--   idx_sales_leads_email
--       -> sales_contact_points UNIQUE (tenant_id, channel, normalized_value).
--
-- SALES_CONVERSIONS
-- ---------------------------------------------------------------------------
-- `sales_conversions.lead_id` was UUID but fed from TEXT lead ids (crm_pg's
-- delete compared `lead_id::text`, the route bound a Uuid's string form).
-- The type is corrected to TEXT and the column becomes a real reference to
-- the mapping column:
--
--   FOREIGN KEY (tenant_id, lead_id)
--       REFERENCES sales_contacts (tenant_id, legacy_lead_id)
--
-- (added NOT VALID so a pre-existing orphan conversion cannot abort a deploy;
-- validated in this transaction when the data allows, with a WARNING naming
-- the orphans otherwise — new rows are enforced either way).
--
-- Fresh-database safety: on a freshly migrated database the old table is
-- empty, the backfill loop is a no-op, and the view/indexes/constraints are
-- created from the canonical schema. All DDL is idempotent-safe (IF EXISTS /
-- IF NOT EXISTS / guarded catalog probes) so re-applying the chain over a
-- database that already went through 223 is a no-op.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Lead columns on the canonical contact.
-- ---------------------------------------------------------------------------
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS legacy_lead_id TEXT;
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS legacy_lead_email TEXT;
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS lead_source TEXT NOT NULL DEFAULT '';
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS lead_score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS lead_notes TEXT;
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS lead_tags JSONB;
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS lead_deal_value DOUBLE PRECISION;
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS lead_snoozed_until TIMESTAMPTZ;
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS lead_last_reply_at TIMESTAMPTZ;
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS lead_priority VARCHAR(50);
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS lead_created_at TIMESTAMPTZ;
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS lead_updated_at TIMESTAMPTZ;
ALTER TABLE sales_contacts ADD COLUMN IF NOT EXISTS lead_search_vector TSVECTOR;

COMMENT ON COLUMN sales_contacts.legacy_lead_id IS
    'The id the retired `sales_leads` table held for this contact. Uniqueness-checked per tenant '
    '(idx_sales_contacts_tenant_legacy_lead_id); this is the stable id the derived sales_leads '
    'view exposes and the target of sales_conversions'' foreign key. NULL means "not a lead".';
COMMENT ON COLUMN sales_contacts.legacy_lead_email IS
    'Read fallback + search projection mirror of the primary email contact point. NEVER an '
    'identity authority: writers mirror sales_contact_points.value here, and the view only uses '
    'it when the contact has no email point (pre-canonical rows).';
COMMENT ON COLUMN sales_contacts.lead_search_vector IS
    'Trigger-maintained single-table search document: to_tsvector(english, full_name || primary '
    'email || account company) — the same expression the retired idx_sales_leads_fts_gin covered. '
    'GIN-indexed as idx_sales_contacts_lead_search_gin.';

CREATE UNIQUE INDEX IF NOT EXISTS idx_sales_contacts_tenant_legacy_lead_id
    ON sales_contacts (tenant_id, legacy_lead_id);

-- CP list ordering by the lead's original creation time.
CREATE INDEX IF NOT EXISTS idx_sales_contacts_tenant_lead_created
    ON sales_contacts (tenant_id, lead_created_at DESC, legacy_lead_id DESC)
    WHERE legacy_lead_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 2. Search vector maintenance.
--
--    `lead_search_vector` is a plain column (not an expression index) so the
--    trigger functions can compute a cross-table document once per write and
--    the GIN index stays a simple single-column index. Triggers cover every
--    canonical writer (in scope and out of scope) so the index can never go
--    stale relative to the view's identity fields.
-- ---------------------------------------------------------------------------
-- One contact: recompute its vector from the same fields the view projects.
CREATE OR REPLACE FUNCTION sales_contacts_refresh_lead_search_vector(p_contact_id UUID)
RETURNS void
LANGUAGE plpgsql
AS $fn$
BEGIN
    UPDATE sales_contacts c
    SET lead_search_vector = to_tsvector(
            'english',
            COALESCE(c.full_name, '') || ' ' ||
            COALESCE(
                (SELECT p.value
                   FROM sales_contact_points p
                  WHERE p.contact_id = c.id
                    AND p.tenant_id = c.tenant_id
                    AND p.channel = 'email'
                  ORDER BY (p.suppressed_at IS NULL) DESC,
                           p.confidence DESC,
                           p.created_at DESC
                  LIMIT 1),
                c.legacy_lead_email,
                ''
            ) || ' ' ||
            COALESCE(
                (SELECT a.company
                   FROM sales_accounts a
                  WHERE a.id = c.account_id
                    AND a.tenant_id = c.tenant_id),
                ''
            )
        )
    WHERE c.id = p_contact_id;
END
$fn$;

-- The contact row itself changed: recompute inline, so the BEFORE trigger
-- applies to the very row being written (no second UPDATE, no recursion).
CREATE OR REPLACE FUNCTION sales_contacts_lead_search_vector_tg()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
    NEW.lead_search_vector := to_tsvector(
        'english',
        COALESCE(NEW.full_name, '') || ' ' ||
        COALESCE(
            (SELECT p.value
               FROM sales_contact_points p
              WHERE p.contact_id = NEW.id
                AND p.tenant_id = NEW.tenant_id
                AND p.channel = 'email'
              ORDER BY (p.suppressed_at IS NULL) DESC,
                       p.confidence DESC,
                       p.created_at DESC
              LIMIT 1),
            NEW.legacy_lead_email,
            ''
        ) || ' ' ||
        COALESCE(
            (SELECT a.company
               FROM sales_accounts a
              WHERE a.id = NEW.account_id
                AND a.tenant_id = NEW.tenant_id),
            ''
        )
    );
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS trg_sales_contacts_lead_search_vector ON sales_contacts;
CREATE TRIGGER trg_sales_contacts_lead_search_vector
    BEFORE INSERT OR UPDATE OF full_name, account_id, legacy_lead_email, legacy_lead_id
    ON sales_contacts
    FOR EACH ROW
    EXECUTE FUNCTION sales_contacts_lead_search_vector_tg();

-- A contact point changed: refresh its owning contact (and the previous owner
-- on a contact_id update).
CREATE OR REPLACE FUNCTION sales_contact_points_lead_search_vector_tg()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM sales_contacts_refresh_lead_search_vector(OLD.contact_id);
        RETURN OLD;
    END IF;
    PERFORM sales_contacts_refresh_lead_search_vector(NEW.contact_id);
    IF TG_OP = 'UPDATE' AND OLD.contact_id IS DISTINCT FROM NEW.contact_id THEN
        PERFORM sales_contacts_refresh_lead_search_vector(OLD.contact_id);
    END IF;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS trg_sales_contact_points_lead_search_vector ON sales_contact_points;
CREATE TRIGGER trg_sales_contact_points_lead_search_vector
    AFTER INSERT OR UPDATE OR DELETE
    ON sales_contact_points
    FOR EACH ROW
    EXECUTE FUNCTION sales_contact_points_lead_search_vector_tg();

-- The account's company changed: refresh every mapped contact of that account.
CREATE OR REPLACE FUNCTION sales_accounts_lead_search_vector_tg()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
    PERFORM sales_contacts_refresh_lead_search_vector(c.id)
    FROM sales_contacts c
    WHERE c.account_id = NEW.id
      AND c.legacy_lead_id IS NOT NULL;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS trg_sales_accounts_lead_search_vector ON sales_accounts;
CREATE TRIGGER trg_sales_accounts_lead_search_vector
    AFTER UPDATE OF company
    ON sales_accounts
    FOR EACH ROW
    EXECUTE FUNCTION sales_accounts_lead_search_vector_tg();

CREATE INDEX IF NOT EXISTS idx_sales_contacts_lead_search_gin
    ON sales_contacts USING GIN (lead_search_vector);

-- ---------------------------------------------------------------------------
-- 3. Backfill: every stored lead becomes its canonical contact mapping.
--
--    Only runs while `sales_leads` is still a relation of kind 'r' (on a
--    fresh database it is empty, so the loop is a no-op). Nothing is deleted
--    here; the old table is dropped only after every row has a mapping.
-- ---------------------------------------------------------------------------
DO $backfill$
DECLARE
    lead           RECORD;
    v_domain       TEXT;
    v_email        TEXT;
    v_account_id   UUID;
    v_contact_id   UUID;
    inserted_account BOOLEAN;
BEGIN
    IF to_regclass('public.sales_leads') IS NULL
       OR (SELECT c.relkind FROM pg_class c WHERE c.oid = to_regclass('public.sales_leads')) <> 'r'
    THEN
        RETURN;
    END IF;

    -- Oldest first: the earliest row owns the id mapping if two rows ever
    -- converged on one canonical contact.
    FOR lead IN
        SELECT * FROM sales_leads
        ORDER BY created_at ASC NULLS FIRST, id ASC
    LOOP
        -- Normalized domain, mirroring normalize_lead_domain(): trim dots,
        -- lowercase, strip one leading www.
        v_domain := lower(btrim(COALESCE(lead.domain, '')));
        v_domain := btrim(v_domain, '.');
        IF v_domain LIKE 'www.%' THEN
            v_domain := substr(v_domain, 5);
        END IF;
        v_domain := btrim(v_domain, '.');

        v_email := lower(btrim(COALESCE(NULLIF(btrim(COALESCE(lead.contact_email, '')), ''),
                                        NULLIF(btrim(COALESCE(lead.email, '')), ''),
                                        '')));
        IF v_domain = '' AND position('@' IN v_email) > 0 THEN
            v_domain := btrim(lower(split_part(v_email, '@', 2)), '.');
            IF v_domain LIKE 'www.%' THEN
                v_domain := substr(v_domain, 5);
            END IF;
        END IF;

        -- Resolve (or create) the account: the old account_id when it still
        -- exists, else the normalized-domain account, else a new one.
        v_account_id := NULL;
        IF lead.account_id IS NOT NULL THEN
            SELECT id INTO v_account_id
              FROM sales_accounts
             WHERE id = lead.account_id AND tenant_id = lead.tenant_id;
        END IF;
        IF v_account_id IS NULL AND v_domain <> '' THEN
            SELECT id INTO v_account_id
              FROM sales_accounts
             WHERE tenant_id = lead.tenant_id AND domain = v_domain;
        END IF;

        inserted_account := FALSE;
        IF v_account_id IS NULL THEN
            v_account_id := gen_random_uuid();
            INSERT INTO sales_accounts
                (id, tenant_id, company, domain, lifecycle, created_at, updated_at)
            VALUES
                (v_account_id,
                 lead.tenant_id,
                 COALESCE(NULLIF(btrim(COALESCE(lead.company_name, '')), ''),
                          NULLIF(v_domain, ''),
                          'unknown'),
                 COALESCE(NULLIF(v_domain, ''), 'unknown.local'),
                 'discovered',
                 COALESCE(lead.created_at, NOW()),
                 COALESCE(lead.updated_at, lead.created_at, NOW()))
            ON CONFLICT (tenant_id, domain) DO UPDATE SET updated_at = NOW()
            RETURNING id INTO v_account_id;
            inserted_account := TRUE;
        END IF;

        -- Resolve the contact: the old contact_id when it still exists and is
        -- not already mapped to a different lead, else the tenant-unique owner
        -- of the address's contact point, else a new contact.
        v_contact_id := NULL;
        IF lead.contact_id IS NOT NULL THEN
            SELECT id INTO v_contact_id
              FROM sales_contacts
             WHERE id = lead.contact_id
               AND tenant_id = lead.tenant_id
               AND (legacy_lead_id IS NULL OR legacy_lead_id = lead.id);
        END IF;
        IF v_contact_id IS NULL AND v_email <> '' THEN
            SELECT c.id INTO v_contact_id
              FROM sales_contact_points p
              JOIN sales_contacts c
                ON c.id = p.contact_id AND c.tenant_id = p.tenant_id
             WHERE p.tenant_id = lead.tenant_id
               AND p.channel = 'email'
               AND p.normalized_value = v_email
               AND (c.legacy_lead_id IS NULL OR c.legacy_lead_id = lead.id)
             LIMIT 1;
        END IF;
        IF v_contact_id IS NULL THEN
            v_contact_id := gen_random_uuid();
            INSERT INTO sales_contacts
                (id, tenant_id, account_id, full_name, created_at, updated_at)
            VALUES
                (v_contact_id,
                 lead.tenant_id,
                 v_account_id,
                 btrim(COALESCE(lead.contact_name, '')),
                 COALESCE(lead.created_at, NOW()),
                 COALESCE(lead.updated_at, lead.created_at, NOW()));
        END IF;

        -- Map the id and carry the lead-only columns. COALESCE keeps richer
        -- canonical values (a non-empty full_name, an existing job_title)
        -- when a contact is shared/reused.
        UPDATE sales_contacts
           SET legacy_lead_id       = lead.id,
               legacy_lead_email    = COALESCE(NULLIF(v_email, ''), legacy_lead_email),
               lead_source          = COALESCE(NULLIF(lead.source, ''), lead_source, ''),
               lead_score           = COALESCE(lead.score, lead_score, 0),
               lead_notes           = COALESCE(lead.notes, lead_notes),
               lead_tags            = COALESCE(lead.tags, lead_tags),
               lead_deal_value      = COALESCE(lead.deal_value, lead_deal_value),
               lead_snoozed_until   = COALESCE(lead.snoozed_until, lead_snoozed_until),
               lead_last_reply_at   = COALESCE(lead.last_reply_at, lead_last_reply_at),
               lead_priority        = COALESCE(lead.priority, lead_priority),
               lead_created_at      = COALESCE(lead.created_at, lead_created_at),
               lead_updated_at      = COALESCE(lead.updated_at, lead_created_at, lead_updated_at),
               full_name            = CASE
                                          WHEN btrim(COALESCE(full_name, '')) = ''
                                          THEN btrim(COALESCE(lead.contact_name, ''))
                                          ELSE full_name
                                      END,
               job_title            = COALESCE(NULLIF(job_title, ''),
                                               NULLIF(btrim(COALESCE(lead.title, '')), '')),
               account_id           = COALESCE(account_id, v_account_id)
         WHERE id = v_contact_id
           AND tenant_id = lead.tenant_id;

        -- The old lead email becomes a canonical contact point with honest
        -- (unverified) provenance when the address is not already on file for
        -- this tenant. If another contact already owns it, the point is left
        -- alone and the view falls back to legacy_lead_email.
        IF v_email <> '' AND position('@' IN v_email) > 0 THEN
            INSERT INTO sales_contact_points
                (id, tenant_id, contact_id, channel, value, normalized_value,
                 verification, confidence, source, created_at, updated_at)
            VALUES
                (gen_random_uuid(),
                 lead.tenant_id,
                 v_contact_id,
                 'email',
                 COALESCE(NULLIF(btrim(COALESCE(lead.contact_email, '')), ''),
                          btrim(COALESCE(lead.email, ''))),
                 v_email,
                 'unverified',
                 0.2,
                 COALESCE(lead.source, ''),
                 COALESCE(lead.created_at, NOW()),
                 COALESCE(lead.updated_at, lead.created_at, NOW()))
            ON CONFLICT (tenant_id, channel, normalized_value) DO NOTHING;
        END IF;

        -- Fill an account company that is empty with the lead's company name
        -- (only for accounts this migration did not just create — a created
        -- account already carries it).
        IF NOT inserted_account AND NULLIF(btrim(COALESCE(lead.company_name, '')), '') IS NOT NULL THEN
            UPDATE sales_accounts
               SET company = lead.company_name,
                   updated_at = NOW()
             WHERE id = v_account_id
               AND tenant_id = lead.tenant_id
               AND btrim(company) = '';
        END IF;
    END LOOP;

    -- One blanket refresh for every mapping, including rows whose triggering
    -- columns did not change above (NULL vector == empty document, but keep
    -- it an explicit tsvector so ts_rank behaves consistently).
    UPDATE sales_contacts c
       SET lead_search_vector = to_tsvector(
               'english',
               COALESCE(c.full_name, '') || ' ' ||
               COALESCE(
                   (SELECT p.value
                      FROM sales_contact_points p
                     WHERE p.contact_id = c.id
                       AND p.tenant_id = c.tenant_id
                       AND p.channel = 'email'
                     ORDER BY (p.suppressed_at IS NULL) DESC,
                              p.confidence DESC,
                              p.created_at DESC
                     LIMIT 1),
                   c.legacy_lead_email,
                   ''
               ) || ' ' ||
               COALESCE(
                   (SELECT a.company
                      FROM sales_accounts a
                     WHERE a.id = c.account_id
                       AND a.tenant_id = c.tenant_id),
                   ''
               )
           )
     WHERE c.legacy_lead_id IS NOT NULL;
END
$backfill$;

-- ---------------------------------------------------------------------------
-- 4. sales_conversions.lead_id: UUID -> TEXT, referencing the mapping column.
-- ---------------------------------------------------------------------------
DO $conversions$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'sales_conversions'
          AND column_name = 'lead_id'
          AND data_type = 'uuid'
    ) THEN
        ALTER TABLE sales_conversions
            ALTER COLUMN lead_id TYPE TEXT USING lead_id::text;
    END IF;
END
$conversions$;

DO $conversions_fk$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_sales_conversions_lead_mapping'
          AND conrelid = 'sales_conversions'::regclass
    ) THEN
        ALTER TABLE sales_conversions
            ADD CONSTRAINT fk_sales_conversions_lead_mapping
            FOREIGN KEY (tenant_id, lead_id)
            REFERENCES sales_contacts (tenant_id, legacy_lead_id)
            NOT VALID;
    END IF;
END
$conversions_fk$;

-- Validate when the (possibly dirty) data allows; a pre-existing orphan
-- conversion must not abort the deploy, and must not be silently deleted
-- either. New rows are enforced by the constraint regardless.
DO $conversions_validate$
DECLARE
    orphans BIGINT;
BEGIN
    ALTER TABLE sales_conversions VALIDATE CONSTRAINT fk_sales_conversions_lead_mapping;
EXCEPTION
    WHEN foreign_key_violation THEN
        SELECT COUNT(*) INTO orphans
          FROM sales_conversions conv
         WHERE NOT EXISTS (
                   SELECT 1 FROM sales_contacts c
                    WHERE c.tenant_id = conv.tenant_id
                      AND c.legacy_lead_id = conv.lead_id
               );
        RAISE WARNING USING
            MESSAGE = format(
                'migration 223: %s sales_conversions row(s) reference a lead id with no canonical '
                'contact mapping; fk_sales_conversions_lead_mapping stays NOT VALID (new rows are '
                'still enforced).', orphans
            ),
            HINT = 'Attribute or delete the orphan conversion rows, then '
                   'ALTER TABLE sales_conversions VALIDATE CONSTRAINT fk_sales_conversions_lead_mapping;';
END
$conversions_validate$;

-- ---------------------------------------------------------------------------
-- 5. Switch sales_leads from a stored table to the derived view.
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS sales_leads;

CREATE OR REPLACE VIEW sales_leads AS
SELECT
    c.legacy_lead_id AS id,
    c.tenant_id,
    COALESCE(a.company, '') AS company_name,
    COALESCE(a.domain, '') AS domain,
    COALESCE(NULLIF(cp.value, ''), NULLIF(c.legacy_lead_email, '')) AS contact_email,
    NULLIF(c.full_name, '') AS contact_name,
    COALESCE(NULLIF(cp.value, ''), NULLIF(c.legacy_lead_email, '')) AS email,
    COALESCE(c.job_title, '') AS title,
    COALESCE(c.lead_score, 0) AS score,
    COALESCE(c.lead_source, '') AS source,
    CASE
        WHEN c.lifecycle = 'customer' OR a.lifecycle = 'customer' THEN 'converted'
        WHEN c.lifecycle = 'meeting_booked' OR e.state = 'meeting_booked' THEN 'demo_scheduled'
        WHEN c.lifecycle = 'replied' OR e.state = 'replied' THEN 'engaged'
        WHEN c.lifecycle = 'do_not_contact'
             OR e.state IN ('suppressed', 'failed') THEN 'lost'
        WHEN c.lifecycle = 'left_company'
             OR a.lifecycle = 'disqualified' THEN 'unqualified'
        WHEN a.lifecycle = 'qualified' THEN 'qualified'
        WHEN a.lifecycle = 'nurturing' THEN 'prospect'
        WHEN e.state IN ('active', 'waiting', 'pending', 'completed')
             OR c.lifecycle = 'snoozed' THEN 'contacted'
        ELSE 'new'
    END AS status,
    COALESCE(c.lead_created_at, c.created_at) AS created_at,
    COALESCE(c.lead_updated_at, c.updated_at) AS updated_at,
    c.lead_notes AS notes,
    COALESCE(c.lead_tags, '[]'::jsonb) AS tags,
    c.lead_deal_value AS deal_value,
    c.lead_snoozed_until AS snoozed_until,
    c.lead_last_reply_at AS last_reply_at,
    c.lead_priority AS priority,
    c.account_id,
    c.id AS contact_id
FROM sales_contacts c
LEFT JOIN sales_accounts a
       ON a.id = c.account_id AND a.tenant_id = c.tenant_id
LEFT JOIN LATERAL (
    SELECT p.value
    FROM sales_contact_points p
    WHERE p.contact_id = c.id
      AND p.tenant_id = c.tenant_id
      AND p.channel = 'email'
    ORDER BY (p.suppressed_at IS NULL) DESC,
             p.confidence DESC,
             p.created_at DESC
    LIMIT 1
) cp ON TRUE
LEFT JOIN LATERAL (
    SELECT e.state
    FROM sales_enrollments e
    WHERE e.contact_id = c.id AND e.tenant_id = c.tenant_id
    ORDER BY CASE
                 WHEN e.state IN ('completed', 'failed', 'suppressed') THEN 1
                 ELSE 0
             END,
             e.updated_at DESC, e.id
    LIMIT 1
) e ON TRUE
WHERE c.legacy_lead_id IS NOT NULL;

COMMENT ON VIEW sales_leads IS
    'DERIVED, READ-ONLY view over the canonical account/contact model (migration 223). '
    'id = sales_contacts.legacy_lead_id (stable old lead id); contact_id/account_id are the '
    'canonical ids; status is derived from contact/account/enrollment lifecycle; lead-only '
    'fields are projected from the sales_contacts.lead_* columns. Writes go to sales_contacts, '
    'sales_accounts, sales_contact_points — never here (a multi-table view is not updatable).';
