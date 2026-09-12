//! Shared integration-test helpers.
//!
//! Convention (follows `tests/can_spam.rs` and api-server's messages.rs
//! tests): tests run against a real Postgres when `SALES_TEST_DATABASE_URL`
//! is set explicitly and reachable, and SOFT-SKIP otherwise, so
//! `cargo test -p sales-autopilot` stays green in environments without
//! infrastructure.
//!
//! The PLATFORM schema (tenants, domains, messages, email_queue,
//! suppressions, templates, metering_events, …) is the CANONICAL production
//! chain (`services/mail-server/migrations`) applied through the REAL
//! production migrator (`migrator::test_support` — audit F01), exactly what
//! every deploy installs; the sales-autopilot own tables are created by
//! `routes::initialize_schema`.

#![allow(dead_code)]

use sqlx::PgPool;
use uuid::Uuid;

/// Name of the dedicated test database this suite provisions. A dedicated
/// database keeps the canonical `_sqlx_migrations` lineage isolated from
/// every other suite's runtime tables; it is dropped, recreated, and
/// canonically migrated once per test process.
const SALES_TEST_DB: &str = "apexmail_sales_test";

/// Process-wide initialization marker: provisioning + migrations run exactly
/// once per test PROCESS. The POOL itself is NOT shared — every
/// `#[tokio::test]` runs on its own runtime, and a sqlx pool is bound to
/// the runtime that created it (sharing it deadlocks cross-runtime with
/// PoolTimedOut). Fresh pool per test, shared initialized database.
static INIT: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();

/// Connect to the test database (None ⇒ soft-skip). The platform schema
/// (canonical chain via the production migrator) and the sales schema
/// (initialize_schema) are prepared once per process; each test gets a
/// fresh pool on the same database. A CONFIGURED provisioning failure
/// aborts the suite (audit F01) instead of reading as a skip.
pub async fn test_pool(test_name: &str) -> Option<PgPool> {
    let ready = INIT
        .get_or_init(|| async {
            let Some(base_url) = shared_test_url() else {
                eprintln!("SKIP [{test_name}]: SALES_TEST_DATABASE_URL unset/unparseable");
                return false;
            };
            let db =
                match migrator::test_support::shared_canonical_db(base_url.as_str(), SALES_TEST_DB)
                    .await
                {
                    Ok(db) => db,
                    // F01: the URL is configured, so an unreachable server or a
                    // failed clone/migration is an infrastructure FAILURE — it
                    // must fail the suite, not silently skip every test.
                    Err(error) => panic!("{}", error.panic_message()),
                };
            let Some(db) = db else {
                eprintln!("SKIP [{test_name}]: unconfigured");
                return false;
            };
            if let Err(e) = sales_autopilot::routes::initialize_schema(&db).await {
                eprintln!("SKIP [{test_name}]: sales schema init failed: {e}");
                return false;
            }
            true
        })
        .await;

    if !ready {
        eprintln!("SKIP [{test_name}]: platform test database unavailable");
        return None;
    }
    // Fresh pool for THIS test's runtime.
    let base = shared_test_url()?;
    connect(&sales_db_url(&base)).await
}

fn shared_test_url() -> Option<url::Url> {
    // F6: no localhost default. A brew/compose postgres listening on the
    // ambient 5432 made these tests run against an unrelated dev database;
    // the env var must name the intended server explicitly (CI points it at
    // an ephemeral container), otherwise the suite soft-skips.
    //
    // `TEST_DATABASE_URL` is accepted as well so the live-DB suites can be
    // run with the same variable api-server's integration tests use.
    let raw = std::env::var("SALES_TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DATABASE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })?;
    url::Url::parse(&raw).ok()
}

fn sales_db_url(base: &url::Url) -> String {
    let mut url = base.clone();
    url.set_path(&format!("/{SALES_TEST_DB}"));
    url.to_string()
}

async fn connect(url: &str) -> Option<PgPool> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
            .connect(url),
    )
    .await
    {
        Ok(Ok(pool)) => Some(pool),
        _ => None,
    }
}

/// Insert a platform tenant (bounded nanoid id, FK target for platform
/// tables) and return its id.
pub async fn insert_test_tenant(pool: &PgPool, suffix: &str) -> String {
    let id = apexmail_lib::id::generate_id("ten", 22);
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status)
         VALUES ($1, $2, $3, 'free', 'active')",
    )
    .bind(&id)
    .bind(format!("Sales Test {suffix}"))
    .bind(format!("sales-{suffix}-{id}"))
    .execute(pool)
    .await
    .expect("failed to insert test tenant");
    id
}

/// Insert a verified + DKIM-ready domain (same fixture shape as api-server's
/// messages.rs tests) so the dispatcher's sender-domain gate passes.
///
/// Canonical `domains` carries a GLOBAL unique index on name (a domain is
/// claimable by one tenant), and the whole suite shares one database — use
/// [`unique_test_domain`] so parallel fixtures never collide on it.
pub async fn insert_verified_domain(pool: &PgPool, tenant_id: &str, domain: &str) -> String {
    // Canonical domains.id is UUID: bind a real UUID, not its text form.
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, ses_verified,
         dkim_selector, dkim_public_key, dkim_private_key)
         VALUES ($1, $2, $3, 'verified', true, true, true, 'test-selector', 'test-public-key', 'dkim:v1:test')",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(domain)
    .execute(pool)
    .await
    .expect("failed to insert verified domain");
    id.to_string()
}

/// A per-fixture unique sender domain (canonical `domains.name` is globally
/// unique and this suite shares one database across parallel tests).
pub fn unique_test_domain() -> String {
    format!(
        "mail-{}.example.com",
        &Uuid::new_v4().simple().to_string()[..12]
    )
}

/// Insert an active campaign template.
pub async fn insert_template(
    pool: &PgPool,
    tenant_id: &str,
    subject: &str,
    html_body: &str,
    text_body: Option<&str>,
) -> String {
    let id = format!("tpl_{}", &Uuid::new_v4().simple().to_string()[..16]);
    sqlx::query(
        "INSERT INTO templates (id, tenant_id, name, slug, subject, html_body, text_body)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(format!("Template {id}"))
    .bind(&id)
    .bind(subject)
    .bind(html_body)
    .bind(text_body)
    .execute(pool)
    .await
    .expect("failed to insert template");
    id
}

/// A valid dispatcher configuration whose sender sits on the given (verified)
/// test domain.
pub fn test_dispatch_config_for(domain: &str) -> sales_autopilot::config::DispatchConfig {
    sales_autopilot::config::DispatchConfig {
        from_email: format!("sales@{domain}"),
        from_name: "ApexMail Sales".into(),
        unsubscribe_secret: "integration-test-unsubscribe-secret-321".into(),
        public_base_url: "http://127.0.0.1:3010".into(),
        unsubscribe_redirect_url: None,
        dispatch_interval_secs: 30,
        dispatch_batch_size: 100,
        dispatch_concurrency: 4,
    }
}

/// Legacy convenience wrapper for suites that seed the literal
/// `example.com` domain exactly once per database.
pub fn test_dispatch_config() -> sales_autopilot::config::DispatchConfig {
    test_dispatch_config_for("example.com")
}

/// A quota gateway that allows every reservation and records nothing. Used by
/// fixtures whose subject is not quota accounting.
#[derive(Debug)]
pub struct AllowAllQuotaGateway;

impl sales_autopilot::dispatcher::QuotaGateway for AllowAllQuotaGateway {
    fn reserve(
        &self,
        _tenant_id: &str,
    ) -> sales_autopilot::dispatcher::QuotaFuture<
        '_,
        Result<sales_autopilot::dispatcher::QuotaReservation, sales_autopilot::types::SalesError>,
    > {
        Box::pin(async {
            Ok(sales_autopilot::dispatcher::QuotaReservation {
                event_id: Uuid::new_v4(),
                recorded_at: chrono::Utc::now(),
            })
        })
    }

    fn rollback(
        &self,
        _tenant_id: &str,
        _reservation: &sales_autopilot::dispatcher::QuotaReservation,
    ) -> sales_autopilot::dispatcher::QuotaFuture<'_, Result<(), sales_autopilot::types::SalesError>>
    {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Canonical sequence-path fixture
// ---------------------------------------------------------------------------
// The surviving send path is:
//   sales_actions (leased, fenced) → SequenceStepHandler → decision_engine::decide
//   → ProductionCampaignDispatcher::enqueue_sequenced → messages + email_queue.
//
// Every integration test that exercises it needs the same canonical fixture
// rows. They are seeded here once so the suites stop hand-rolling subtly
// different versions:
//
//   sales_accounts / sales_contacts / sales_contact_points (email, verified)
//   sales_sequences + approved active version + one email step
//   sales_enrollments + sales_step_executions (canonical idempotency key)
//   sales_sender_identities (sales_outbound) + sales_sender_health
//   sales_autonomy_state (autonomous_guarded)
//   an approved, in-date `allowed` legal policy for [`TEST_JURISDICTION`]
//   a verified platform `domains` row for the sender identity's domain

/// Jurisdiction used by the shared sequence fixture's account/contact.
///
/// Deliberately not a real ISO 3166-1 alpha-2 code and not in the EU/EEA set,
/// so it can never collide with the fail-closed seed policies from migration
/// 200 (`EU` / `UNKNOWN`, both `approval_required`). The fixture's policy row
/// is `allowed`, which is what lets an `autonomous_guarded` send execute.
pub const TEST_JURISDICTION: &str = "QZ";

/// Ensure the shared `allowed` email policy for [`TEST_JURISDICTION`] exists.
///
/// Migration 200 seeds only fail-closed defaults, so an executing fixture
/// needs its own approved row. Idempotent and safe under the parallel,
/// shared-database test model: a concurrent insert of the same
/// `(jurisdiction, channel, contact_type, version)` is a no-op.
pub async fn ensure_allowed_jurisdiction_policy(pool: &PgPool) -> Uuid {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sales_jurisdiction_policies \
         WHERE jurisdiction = $1 AND channel = 'email' \
           AND contact_type = 'b2b_professional' AND version = 1",
    )
    .bind(TEST_JURISDICTION)
    .fetch_optional(pool)
    .await
    .expect("look up fixture jurisdiction policy");
    if let Some(id) = existing {
        return id;
    }

    sqlx::query(
        "INSERT INTO sales_jurisdiction_policies \
             (id, jurisdiction, channel, contact_type, decision, basis, version, \
              approved_by, approved_at, valid_from) \
         VALUES ($1, $2, 'email', 'b2b_professional', 'allowed', 'legitimate_interest', 1, \
                 'integration-fixture', NOW(), NOW()) \
         ON CONFLICT (jurisdiction, channel, contact_type, version) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(TEST_JURISDICTION)
    .execute(pool)
    .await
    .expect("insert fixture jurisdiction policy");

    sqlx::query_scalar(
        "SELECT id FROM sales_jurisdiction_policies \
         WHERE jurisdiction = $1 AND channel = 'email' \
           AND contact_type = 'b2b_professional' AND version = 1",
    )
    .bind(TEST_JURISDICTION)
    .fetch_one(pool)
    .await
    .expect("fixture jurisdiction policy must exist after insert")
}

/// Knobs for [`seed_sequence_fixture`]. `Default` is a fully working
/// happy-path send fixture; each `without_*`/`with_*` method removes or
/// changes exactly one thing a test wants to observe.
#[derive(Debug, Clone)]
pub struct SequenceFixtureOptions {
    /// Create a platform template and point the step at it.
    pub template: bool,
    /// Insert the verified platform `domains` row for the sender domain(s).
    /// Turning this off models an unverified sender domain.
    pub verified_domain: bool,
    /// Insert an active `sales_outbound` sender identity (plus health row).
    pub sender_identity: bool,
    /// `sales_autonomy_state.mode`; `None` leaves no row (disabled, fail closed).
    pub autonomy_mode: Option<&'static str>,
    /// `sales_contact_points.verification` for the email point.
    pub verification: &'static str,
    /// Also insert the enrollment + first step execution.
    pub enroll: bool,
    /// Override the recipient address (default: unique per fixture).
    pub email: Option<String>,
    /// Send the sequence mail from a SECOND verified domain, proving the
    /// resolved sender identity (not the deployment-wide
    /// `SALES_CAMPAIGN_FROM_EMAIL`) is the envelope sender.
    pub identity_domain: Option<String>,
}

impl Default for SequenceFixtureOptions {
    fn default() -> Self {
        Self {
            template: true,
            verified_domain: true,
            sender_identity: true,
            autonomy_mode: Some("autonomous_guarded"),
            verification: "valid",
            enroll: true,
            email: None,
            identity_domain: None,
        }
    }
}

impl SequenceFixtureOptions {
    pub fn without_template(mut self) -> Self {
        self.template = false;
        self
    }

    pub fn without_verified_domain(mut self) -> Self {
        self.verified_domain = false;
        self
    }

    pub fn without_sender_identity(mut self) -> Self {
        self.sender_identity = false;
        self
    }

    pub fn without_autonomy(mut self) -> Self {
        self.autonomy_mode = None;
        self
    }

    pub fn without_enrollment(mut self) -> Self {
        self.enroll = false;
        self
    }

    pub fn with_verification(mut self, verification: &'static str) -> Self {
        self.verification = verification;
        self
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn with_identity_domain(mut self, domain: impl Into<String>) -> Self {
        self.identity_domain = Some(domain.into());
        self
    }
}

/// A fully seeded canonical sequence send fixture. Row provenance (for the
/// column-level evidence, see the migration references in the seed function):
/// `sales_accounts` (200:212), `sales_contacts` (200:250), `sales_contact_points`
/// (200:279), `sales_sequences` (200:434), `sales_sequence_versions` (200:448),
/// `sales_sequence_steps` (200:464), `sales_enrollments` (200:491),
/// `sales_step_executions` (200:523), `sales_sender_identities` (200:635),
/// `sales_sender_health` (200:656).
#[derive(Debug, Clone)]
pub struct SequenceFixture {
    pub tenant_id: String,
    pub account_id: Uuid,
    pub contact_id: Uuid,
    pub contact_point_id: Uuid,
    pub email: String,
    pub sequence_id: Uuid,
    pub version_id: Uuid,
    pub step_id: Uuid,
    pub enrollment_id: Option<Uuid>,
    pub step_execution_id: Option<Uuid>,
    pub sender_id: Option<Uuid>,
    pub policy_id: Uuid,
    /// The fixture's own unique domain (also the deployment-wide dispatcher
    /// config domain for tests that build one).
    pub domain: String,
    /// The resolved sender identity's `from_email`.
    pub sender_from_email: String,
    pub template_id: Option<String>,
}

/// Seed the canonical sequence fixture for `tenant_id` (which must already
/// exist in `tenants` as far as platform columns are concerned — see
/// [`insert_test_tenant`]).
pub async fn seed_sequence_fixture(
    pool: &PgPool,
    tenant_id: &str,
    opts: SequenceFixtureOptions,
) -> SequenceFixture {
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let domain = unique_test_domain();
    let identity_domain = opts
        .identity_domain
        .clone()
        .unwrap_or_else(|| domain.clone());
    let sender_from_email = format!("sales@{identity_domain}");
    let account_id = Uuid::new_v4();
    let contact_id = Uuid::new_v4();
    let contact_point_id = Uuid::new_v4();
    let sequence_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();
    let step_id = Uuid::new_v4();
    let email = opts
        .email
        .clone()
        .unwrap_or_else(|| format!("prospect-{contact_id}@example.com"));
    let policy_id = ensure_allowed_jurisdiction_policy(pool).await;

    if opts.verified_domain {
        insert_verified_domain(pool, tenant_id, &identity_domain).await;
        if identity_domain != domain {
            insert_verified_domain(pool, tenant_id, &domain).await;
        }
    }

    sqlx::query(
        "INSERT INTO sales_accounts \
             (id, tenant_id, company, domain, country, country_confidence, lifecycle) \
         VALUES ($1, $2, $3, $4, $5, 0.95, 'discovered')",
    )
    .bind(account_id)
    .bind(tenant_id)
    .bind(format!("Fixture Co {suffix}"))
    .bind(format!("acct-{suffix}.example"))
    .bind(TEST_JURISDICTION)
    .execute(pool)
    .await
    .expect("insert sales_accounts fixture");

    sqlx::query(
        "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name, country) \
         VALUES ($1, $2, $3, 'Fixture Prospect', $4)",
    )
    .bind(contact_id)
    .bind(tenant_id)
    .bind(account_id)
    .bind(TEST_JURISDICTION)
    .execute(pool)
    .await
    .expect("insert sales_contacts fixture");

    sqlx::query(
        "INSERT INTO sales_contact_points \
             (id, tenant_id, contact_id, channel, value, normalized_value, verification, \
              confidence, source) \
         VALUES ($1, $2, $3, 'email', $4, lower($4), $5, 0.95, 'integration-fixture')",
    )
    .bind(contact_point_id)
    .bind(tenant_id)
    .bind(contact_id)
    .bind(&email)
    .bind(opts.verification)
    .execute(pool)
    .await
    .expect("insert sales_contact_points fixture");

    sqlx::query(
        "INSERT INTO sales_sequences (id, tenant_id, name, status) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind(sequence_id)
    .bind(tenant_id)
    .bind(format!("Fixture Sequence {suffix}"))
    .execute(pool)
    .await
    .expect("insert sales_sequences fixture");

    // `approved_by`/`approved_at` are required by
    // `sequences::load_active_version` (and "active" by the status CHECK).
    sqlx::query(
        "INSERT INTO sales_sequence_versions \
             (id, tenant_id, sequence_id, version, status, locale, approved_by, approved_at) \
         VALUES ($1, $2, $3, 1, 'active', 'en', 'integration-fixture', NOW())",
    )
    .bind(version_id)
    .bind(tenant_id)
    .bind(sequence_id)
    .execute(pool)
    .await
    .expect("insert sales_sequence_versions fixture");

    let template_id = if opts.template {
        Some(
            insert_template(
                pool,
                tenant_id,
                "Hi {{first_name}} from {{company}}",
                "<html><body><p>Hello {{first_name}}, meet {{company}}!</p>\
                 <a href=\"https://example.com/x\">x</a></body></html>",
                Some("Hello {{name}}, plain text."),
            )
            .await,
        )
    } else {
        None
    };

    sqlx::query(
        "INSERT INTO sales_sequence_steps \
             (id, tenant_id, version_id, step_index, kind, template_id, \
              min_delay_secs, max_delay_secs, sender_pool) \
         VALUES ($1, $2, $3, 0, 'email', $4, 0, 0, 'sales_outbound')",
    )
    .bind(step_id)
    .bind(tenant_id)
    .bind(version_id)
    .bind(template_id.as_deref())
    .execute(pool)
    .await
    .expect("insert sales_sequence_steps fixture");

    let sender_id = if opts.sender_identity {
        let sender_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_sender_identities \
                 (id, tenant_id, pool, from_email, from_name, domain, status, daily_limit) \
             VALUES ($1, $2, 'sales_outbound', $3, 'Fixture Sender', $4, 'active', 200)",
        )
        .bind(sender_id)
        .bind(tenant_id)
        .bind(&sender_from_email)
        .bind(&identity_domain)
        .execute(pool)
        .await
        .expect("insert sales_sender_identities fixture");

        // The pre-send sender-health gate fails closed without a row.
        sqlx::query(
            "INSERT INTO sales_sender_health \
                 (id, tenant_id, sender_identity_id, health_score, state) \
             VALUES (gen_random_uuid(), $1, $2, 0.99, 'healthy')",
        )
        .bind(tenant_id)
        .bind(sender_id)
        .execute(pool)
        .await
        .expect("insert sales_sender_health fixture");
        Some(sender_id)
    } else {
        None
    };

    if let Some(mode) = opts.autonomy_mode {
        sqlx::query(
            "INSERT INTO sales_autonomy_state (tenant_id, mode, kill_switch, updated_at) \
             VALUES ($1, $2, FALSE, NOW()) \
             ON CONFLICT (tenant_id) DO UPDATE \
                SET mode = EXCLUDED.mode, kill_switch = FALSE, updated_at = NOW()",
        )
        .bind(tenant_id)
        .bind(mode)
        .execute(pool)
        .await
        .expect("insert sales_autonomy_state fixture");
    }

    let (enrollment_id, step_execution_id) = if opts.enroll {
        let enrollment_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_enrollments \
                 (id, tenant_id, sequence_version_id, account_id, contact_id, contact_point_id, \
                  state, current_step_index) \
             VALUES ($1, $2, $3, $4, $5, $6, 'active', 0)",
        )
        .bind(enrollment_id)
        .bind(tenant_id)
        .bind(version_id)
        .bind(account_id)
        .bind(contact_id)
        .bind(contact_point_id)
        .execute(pool)
        .await
        .expect("insert sales_enrollments fixture");

        let step_execution_id =
            seed_step_execution(pool, tenant_id, enrollment_id, version_id, step_id, 0).await;
        (Some(enrollment_id), Some(step_execution_id))
    } else {
        (None, None)
    };

    SequenceFixture {
        tenant_id: tenant_id.to_string(),
        account_id,
        contact_id,
        contact_point_id,
        email,
        sequence_id,
        version_id,
        step_id,
        enrollment_id,
        step_execution_id,
        sender_id,
        policy_id,
        domain,
        sender_from_email,
        template_id,
    }
}

/// Insert one more email step into an existing fixture version (used to prove
/// a second legitimate touch to the same recipient is a distinct send
/// identity).
pub async fn add_email_step(
    pool: &PgPool,
    tenant_id: &str,
    version_id: Uuid,
    step_index: i32,
    template_id: &str,
) -> Uuid {
    let step_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_sequence_steps \
             (id, tenant_id, version_id, step_index, kind, template_id, \
              min_delay_secs, max_delay_secs, sender_pool) \
         VALUES ($1, $2, $3, $4, 'email', $5, 0, 0, 'sales_outbound')",
    )
    .bind(step_id)
    .bind(tenant_id)
    .bind(version_id)
    .bind(step_index)
    .bind(template_id)
    .execute(pool)
    .await
    .expect("insert additional sales_sequence_steps fixture");
    step_id
}

/// Insert a `scheduled` step execution with the canonical logical identity
/// `sa:{enrollment}:{version}:{step}:primary:default`.
pub async fn seed_step_execution(
    pool: &PgPool,
    tenant_id: &str,
    enrollment_id: Uuid,
    version_id: Uuid,
    step_id: Uuid,
    step_index: i32,
) -> Uuid {
    let step_execution_id = Uuid::new_v4();
    let idempotency_key = sales_autopilot::sequences::sales_step_idempotency_key(
        enrollment_id,
        version_id,
        step_id,
        "primary",
        "default",
    );
    sqlx::query(
        "INSERT INTO sales_step_executions \
             (id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id, step_index, \
              attempt_kind, variant, state, idempotency_key, scheduled_for, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'primary', 'default', 'scheduled', $7, NOW(), NOW(), NOW())",
    )
    .bind(step_execution_id)
    .bind(tenant_id)
    .bind(enrollment_id)
    .bind(version_id)
    .bind(step_id)
    .bind(step_index)
    .bind(&idempotency_key)
    .execute(pool)
    .await
    .expect("insert sales_step_executions fixture");
    step_execution_id
}

/// Insert a minimal persisted Decision Packet for dispatcher-level tests that
/// call `enqueue_sequenced` directly (without running
/// `decision_engine::decide`). The typed provenance FKs on `messages` /
/// `email_queue` (`fk_messages_sales_decision`, migration 202 line 46) require
/// a real row.
pub async fn insert_fixture_decision(pool: &PgPool, tenant_id: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_decisions \
             (id, tenant_id, action, autonomy_mode, rationale, enforcement, review_status) \
         VALUES ($1, $2, 'contact', 'autonomous_guarded', \
                 'dispatcher integration fixture', 'execute', 'not_required')",
    )
    .bind(id)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert sales_decisions fixture");
    id
}

/// Enqueue the production `send_step` action for a step execution
/// (`sa-send:{step_execution_id}`, the key `enrollments::start_outreach`
/// writes), returning the durable queue row.
pub async fn enqueue_send_step_action(
    pool: &PgPool,
    tenant_id: &str,
    step_execution_id: Uuid,
) -> sales_autopilot::actions::SalesAction {
    let queue = sales_autopilot::actions::ActionQueue::new(
        pool.clone(),
        format!("fixture-enqueue-{step_execution_id}"),
    );
    queue
        .enqueue(
            tenant_id,
            sales_autopilot::actions::action_type::SEND_STEP,
            sales_autopilot::actions::entity_type::STEP_EXECUTION,
            step_execution_id,
            &format!("sa-send:{step_execution_id}"),
            serde_json::json!({ "stepExecutionId": step_execution_id }),
            chrono::Utc::now(),
            100,
            None,
        )
        .await
        .expect("enqueue send_step action")
}

/// Claim ONE specific queued action with the queue's own claim semantics
/// (state → executing, fresh per-claim `lease_token`, live lease).
///
/// Deliberately not `ActionQueue::claim(limit)`: the test database is shared
/// by parallel suites, and a broad claim would lease unrelated work.
pub async fn claim_specific_action(
    pool: &PgPool,
    worker_id: &str,
    action_id: Uuid,
) -> Option<sales_autopilot::actions::LeasedAction> {
    #[derive(sqlx::FromRow)]
    struct ClaimedRow {
        id: Uuid,
        tenant_id: String,
        action_type: String,
        entity_type: String,
        entity_id: Uuid,
        due_at: chrono::DateTime<chrono::Utc>,
        priority: i16,
        state: String,
        attempt: i32,
        max_attempts: i32,
        lease_owner: Option<String>,
        lease_token: Option<Uuid>,
        lease_expires_at: Option<chrono::DateTime<chrono::Utc>>,
        idempotency_key: String,
        payload: serde_json::Value,
        decision_id: Option<Uuid>,
        last_error: Option<String>,
        created_at: chrono::DateTime<chrono::Utc>,
        completed_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    let row: ClaimedRow = sqlx::query_as::<_, ClaimedRow>(
        "UPDATE sales_actions \
         SET state = 'executing', \
             lease_owner = $2, \
             lease_token = gen_random_uuid(), \
             lease_expires_at = NOW() + make_interval(secs => $3::double precision), \
             attempt = attempt + 1 \
         WHERE id = $1 AND state = 'queued' AND due_at <= NOW() \
         RETURNING *",
    )
    .bind(action_id)
    .bind(worker_id)
    .bind(sales_autopilot::actions::DEFAULT_LEASE_SECS as f64)
    .fetch_optional(pool)
    .await
    .expect("claim specific action")?;

    Some(sales_autopilot::actions::LeasedAction {
        action: sales_autopilot::actions::SalesAction {
            id: row.id,
            tenant_id: row.tenant_id,
            action_type: row.action_type,
            entity_type: row.entity_type,
            entity_id: row.entity_id,
            due_at: row.due_at,
            priority: row.priority,
            state: row.state,
            attempt: row.attempt,
            max_attempts: row.max_attempts,
            lease_owner: row.lease_owner,
            lease_expires_at: row.lease_expires_at,
            idempotency_key: row.idempotency_key,
            payload: row.payload,
            decision_id: row.decision_id,
            last_error: row.last_error,
            created_at: row.created_at,
            completed_at: row.completed_at,
        },
        lease_owner: worker_id.to_string(),
        // The claim always issues a real token (mirrors ActionQueue::claim).
        lease_token: row.lease_token.expect("claim must issue a lease token"),
    })
}

/// Run one step execution through the REAL production chain: durable action →
/// [`sales_autopilot::sequence_worker::SequenceStepHandler`] → decision engine
/// → `ProductionCampaignDispatcher::enqueue_sequenced`. Finishes the action
/// with the handler's outcome (fenced), exactly like `actions::tick` does.
pub async fn run_send_step(
    pool: &PgPool,
    dispatcher: std::sync::Arc<sales_autopilot::dispatcher::ProductionCampaignDispatcher>,
    tenant_id: &str,
    step_execution_id: Uuid,
) -> sales_autopilot::actions::ActionOutcome {
    let action = enqueue_send_step_action(pool, tenant_id, step_execution_id).await;
    let worker_id = format!("sequence-worker-{}", Uuid::new_v4().simple());
    let leased = claim_specific_action(pool, &worker_id, action.id)
        .await
        .expect("the just-enqueued action must be claimable");

    let handler =
        sales_autopilot::sequence_worker::SequenceStepHandler::new(pool.clone(), dispatcher);
    let outcome = sales_autopilot::actions::ActionHandler::handle(&handler, &leased).await;

    let queue = sales_autopilot::actions::ActionQueue::new(pool.clone(), worker_id);
    let finished = queue
        .finish(&leased.fence(), outcome.clone())
        .await
        .expect("finish the claimed action");
    assert!(finished, "the worker still owned its live lease");
    outcome
}

/// Insert a sender identity in an explicit pool (fixtures that must prove
/// which pool a send selected, or that no sales sender exists at all).
pub async fn insert_sender_identity(
    pool: &PgPool,
    tenant_id: &str,
    pool_name: &str,
    from_email: &str,
    domain: &str,
    status: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_sender_identities \
             (id, tenant_id, pool, from_email, from_name, domain, status, daily_limit) \
         VALUES ($1, $2, $3, $4, 'Fixture Sender', $5, $6, 200)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(pool_name)
    .bind(from_email)
    .bind(domain)
    .bind(status)
    .execute(pool)
    .await
    .unwrap_or_else(|error| panic!("insert sender identity ({pool_name}) failed: {error}"));
    id
}

/// Seed an open pipeline opportunity so the sequence planner's §28 economic
/// gate has a real positive expected value (a fixture with no pipeline scores
/// a negative EV once a score row is stored, and the next-best-action planner
/// then refuses to send).
pub async fn seed_open_opportunity(
    pool: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    amount_eur: f64,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_opportunities (id, tenant_id, account_id, stage, amount_eur) \
         VALUES ($1, $2, $3, 'open', $4)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(account_id)
    .bind(amount_eur)
    .execute(pool)
    .await
    .expect("seed open opportunity");
    id
}

/// Seed `count` fresh, high-confidence evidence rows for an account, so the
/// sequence planner's §12/§28 evidence floor is satisfied and it plans a real
/// send instead of a research/enrichment action.
pub async fn seed_live_evidence(
    pool: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
    count: usize,
) -> Vec<Uuid> {
    let mut ids = Vec::with_capacity(count);
    for index in 0..count {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_evidence \
                 (id, tenant_id, account_id, proposition, confidence, source_kind, observed_at) \
             VALUES ($1, $2, $3, $4, 0.9, 'http_fetch', NOW())",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(account_id)
        .bind(format!("release-gate evidence {index}"))
        .execute(pool)
        .await
        .expect("seed live evidence");
        ids.push(id);
    }
    ids
}

// ---------------------------------------------------------------------------
// Control-plane handler fixture
// ---------------------------------------------------------------------------

/// Build an [`AppState`](sales_autopilot::routes::AppState) so control-plane
/// handlers can be driven directly (no HTTP hop, no service token).
///
/// The dispatcher is deliberately absent: the review/approval handlers never
/// touch it, and a `None` dispatcher is the deployment shape that leaves
/// queued work untouched.
pub fn app_state(pool: &PgPool) -> sales_autopilot::routes::AppState {
    let dispatch = test_dispatch_config();
    sales_autopilot::routes::AppState {
        db: pool.clone(),
        redis: deadpool_redis::Config::from_url("redis://127.0.0.1:16379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool construction"),
        crm: sales_autopilot::crm::CrmBackend::postgres(pool.clone()),
        enrichment: sales_autopilot::enrichment::EnrichmentService::mock(),
        campaigns: sales_autopilot::campaigns::CampaignManager::new(50, pool.clone()),
        dispatcher: None,
        calendar: sales_autopilot::calendar::CalendarService::new(pool.clone()),
        inbox: sales_autopilot::inbox::InboxManager::new(pool.clone()),
        service_token: "release-gate-test-token".into(),
        config: sales_autopilot::config::SalesConfig {
            dispatch,
            ..sales_autopilot::config::SalesConfig::default()
        },
        rate_limit_fallback: std::sync::Arc::new(parking_lot::Mutex::new(
            std::collections::HashMap::new(),
        )),
        intelligence: std::sync::Arc::new(sales_autopilot::intelligence::OfflineIntelligence::new()),
        strategist: std::sync::Arc::new(sales_autopilot::personalization::MessageStrategist::new(
            pool.clone(),
            sales_autopilot::knowledge::SalesKnowledgeBase::canonical(),
        )),
    }
}

/// Drive the REAL `control::review_decision` handler (the only path that may
/// approve or reject an `await_approval` decision) and return its JSON body.
pub async fn review_decision(
    pool: &PgPool,
    tenant_id: &str,
    decision_id: Uuid,
    outcome: &str,
    note: Option<&str>,
) -> Result<serde_json::Value, sales_autopilot::types::SalesError> {
    let state = std::sync::Arc::new(app_state(pool));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-tenant-id",
        axum::http::HeaderValue::from_str(tenant_id).expect("tenant id is a valid header value"),
    );
    let response = sales_autopilot::control::review_decision(
        axum::extract::State(state),
        headers,
        axum::extract::Path(decision_id.to_string()),
        axum::Json(sales_autopilot::control::ReviewBody {
            outcome: outcome.to_string(),
            note: note.map(str::to_string),
        }),
    )
    .await?;
    Ok(response.0)
}

/// Delete every row a canonical fixture/test may have created for `tenant_id`.
///
/// Ordered child → parent so FK constraints never block the cleanup. The
/// shared `sales_jurisdiction_policies` fixture row is deliberately NOT
/// deleted (it is global and reused by every fixture).
pub async fn cleanup_tenant(pool: &PgPool, tenant_id: &str) {
    for statement in [
        "DELETE FROM email_queue WHERE tenant_id = $1",
        "DELETE FROM messages WHERE tenant_id = $1",
        "DELETE FROM sales_actions WHERE tenant_id = $1",
        "DELETE FROM sales_outcomes WHERE tenant_id = $1",
        "DELETE FROM sales_opportunities WHERE tenant_id = $1",
        "DELETE FROM sales_sender_events WHERE tenant_id = $1",
        "DELETE FROM sales_evidence WHERE tenant_id = $1",
        "DELETE FROM sales_scores WHERE tenant_id = $1",
        "DELETE FROM sales_experiment_outcomes WHERE experiment_id IN \
             (SELECT id FROM sales_experiments WHERE tenant_id = $1)",
        "DELETE FROM sales_experiment_arms WHERE tenant_id = $1",
        "DELETE FROM sales_experiments WHERE tenant_id = $1",
        "DELETE FROM sales_contact_policy_decisions WHERE tenant_id = $1",
        "DELETE FROM sales_decisions WHERE tenant_id = $1",
        "DELETE FROM sales_step_executions WHERE tenant_id = $1",
        "DELETE FROM sales_enrollments WHERE tenant_id = $1",
        "DELETE FROM sales_sequence_steps WHERE tenant_id = $1",
        "DELETE FROM sales_sequence_versions WHERE tenant_id = $1",
        "DELETE FROM sales_sequences WHERE tenant_id = $1",
        "DELETE FROM sales_contact_points WHERE tenant_id = $1",
        "DELETE FROM sales_contacts WHERE tenant_id = $1",
        "DELETE FROM sales_accounts WHERE tenant_id = $1",
        "DELETE FROM sales_sender_health WHERE tenant_id = $1",
        "DELETE FROM sales_sender_identities WHERE tenant_id = $1",
        "DELETE FROM sales_autonomy_state WHERE tenant_id = $1",
        "DELETE FROM sales_unsubscribes WHERE tenant_id = $1",
        "DELETE FROM sales_unsubscribe_tokens WHERE tenant_id = $1",
        "DELETE FROM suppressions WHERE tenant_id = $1",
        "DELETE FROM domains WHERE tenant_id = $1",
        "DELETE FROM templates WHERE tenant_id = $1",
        "DELETE FROM sales_campaign_recipients WHERE campaign_id IN \
             (SELECT id FROM sales_campaigns WHERE tenant_id = $1)",
        "DELETE FROM sales_campaigns WHERE tenant_id = $1",
        "DELETE FROM sales_inbox_messages WHERE tenant_id = $1",
        "DELETE FROM sales_leads WHERE tenant_id = $1",
        "DELETE FROM tenants WHERE id = $1",
    ] {
        sqlx::query(statement)
            .bind(tenant_id)
            .execute(pool)
            .await
            .unwrap_or_else(|error| panic!("cleanup `{statement}` failed: {error}"));
    }
}
